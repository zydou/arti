#[test]
fn apply_tricky() {
    let pre = include_str!("../testdata/consensus1.txt");
    let diff = include_str!("../testdata/diff1.txt");
    let post = include_str!("../testdata/consensus2.txt");

    let result = tor_consdiff::apply_diff(pre, diff, None).unwrap();
    assert_eq!(result.to_string(), post);
}

#[test]
fn gen_tricky() {
    let base = include_str!("../testdata/consensus1.txt");
    let target = include_str!("../testdata/consensus2.txt");
    let diff = tor_consdiff::gen_cons_diff(base, target).unwrap();

    assert_eq!(
        diff.lines().take(2).collect::<Vec<_>>(),
        [
            "network-status-diff-version 1",
            "hash B03DA3ACA1D3C1D083E3FF97873002416EBD81A058B406D5C5946EAB53A79663 F6789F35B6B3BA58BB23D29E53A8ED6CBB995543DBE075DD5671481C4BA677FB"
        ]
    );

    // Should not be necessary because gen_cons_diff already does that.
    let result = tor_consdiff::apply_diff(base, &diff, None).unwrap();
    assert_eq!(result.to_string(), target);
}
