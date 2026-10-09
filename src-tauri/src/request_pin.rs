//! SECURITY (Windows only): refuse every webview request to a host other than
//! the app's own before it reaches the network.
//!
//! `navigation_pin` cancels a navigation off the app's origin in WebView2's
//! `NavigationStarting`, and the page stays put, but WebView2 has already sent
//! that navigation's request by then. Measured on WebView2 154, `location.href`,
//! `location.assign`, a link click and a meta refresh each delivered their URL,
//! query string included, to a foreign server despite the cancel, so a
//! compromised page could still exfiltrate through the URL. `WebResourceRequested`
//! is raised before a request goes out; answering foreign requests there with a
//! local 403 means they never leave the machine. WKWebView and WebKitGTK do not
//! send a cancelled navigation's request, so this layer is Windows-only.
//!
//! wry registers its own `WebResourceRequested` handler for the app's custom
//! protocols and ignores every URI that is not its own, so the `*` filter here
//! coexists with it: requests for the app's own origins are left untouched for
//! wry to serve.

use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2Controller, ICoreWebView2Environment, ICoreWebView2_22,
    COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL, COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS_ALL,
};
use webview2_com::{take_pwstr, WebResourceRequestedEventHandler};
use windows::core::{Interface, HSTRING, PWSTR};

/// Install the filter and handler on one webview. `allowed` is
/// `crate::app_request_origins` (plus `devUrl` in a `tauri dev` build).
pub fn install(
    controller: ICoreWebView2Controller,
    environment: ICoreWebView2Environment,
    allowed: Vec<tauri::Url>,
) -> windows::core::Result<()> {
    // SAFETY: WebView2 COM calls on interfaces Tauri handed us, made on the
    // webview's own thread (`with_webview` runs there), as wry itself does.
    unsafe {
        let webview = controller.CoreWebView2()?;
        let filter = HSTRING::from("*");
        // The newer API also covers requests from iframes and shared workers,
        // which the original filter misses (WebView2Feedback#1114).
        if let Ok(webview_22) = webview.cast::<ICoreWebView2_22>() {
            webview_22.AddWebResourceRequestedFilterWithRequestSourceKinds(
                &filter,
                COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL,
                COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS_ALL,
            )?;
        } else {
            webview.AddWebResourceRequestedFilter(&filter, COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL)?;
        }
        let mut token = 0i64;
        webview.add_WebResourceRequested(
            &WebResourceRequestedEventHandler::create(Box::new(move |_, args| {
                let Some(args) = args else {
                    return Ok(());
                };
                let mut uri = PWSTR::null();
                args.Request()?.Uri(&mut uri)?;
                let uri = take_pwstr(uri);
                if crate::is_app_request(&uri, &allowed) {
                    return Ok(());
                }
                eprintln!("refused a request away from the app to {}", crate::origin_for_log(&uri));
                let response = environment.CreateWebResourceResponse(
                    None,
                    403,
                    &HSTRING::from("Forbidden"),
                    &HSTRING::new(),
                )?;
                args.SetResponse(&response)
            })),
            &mut token,
        )
    }
}
