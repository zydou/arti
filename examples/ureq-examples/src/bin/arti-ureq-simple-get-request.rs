// Make GET request over the Tor network using ureq.

const TEST_URL: &str = "https://check.torproject.org/api/ip";

fn main() {
    // Get the ureq agent.
    let ureq_agent = arti_ureq::default_agent().expect("Failed to create ureq agent.");

    // Make request.
    let request = ureq_agent.get(TEST_URL).call();

    let mut request = match request {
        Ok(request) => request,
        Err(err) => {
            eprintln!("Failed to make request: {err}");
            return;
        }
    };

    // Get response body.
    let response = request
        .body_mut()
        .read_to_string()
        .expect("Failed to read body.");

    // Will output if request was made using Tor.
    println!("Response: {response}");
}
