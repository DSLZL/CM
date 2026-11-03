// Included only in the separate Core libtest executable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires frozen hosted Linux SDK fixtures"]
async fn cm_sdk_seams_protocol() {
    let case = std::env::var("CM_SEAMS_PROBE_CASE").expect("case");
    if case.starts_with("stream-probe-") {
        let home = std::path::PathBuf::from(std::env::var_os("CM_SEAMS_PROFILE").expect("profile"));
        cm_host_adapter::sdk_stream_probe(&home, &case).await;
    } else {
        cm_runtime::sdk_seams_probe::run().await;
    }
}
