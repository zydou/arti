// Make POST request over the Tor network using ureq.

const TEST_URL: &str = "https://check.torproject.org/api/ip";

fn main() {
    // Get the ureq agent.
    let ureq_agent = arti_ureq::default_agent().expect("Failed to create ureq agent.");

    // Make request.
    let mut request = ureq_agent
        .post(TEST_URL)
        .send("Hello, world!")
        .expect("Failed to make request.");

    let response = request
        .body_mut()
        .read_to_string()
        .expect("Failed to read body.");

    // Will output if request was made using Tor.
    println!("Response: {response}");
}
