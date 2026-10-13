use revm::primitives::Log;

pub fn test_log_api(log: &Log) {
    let _addr = log.address;
    let _topics = log.topics();
    let _data = &log.data.data;
}
