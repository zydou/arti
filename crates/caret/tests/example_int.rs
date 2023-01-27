use caret::caret_int;

caret_int! {
    struct Demo(u16) {
        A = 8,
        B = 10,
        C = 7,
        DEE = 999,
    }
}

#[test]
fn test_int_ops() {
    let aval: u16 = Demo::A.into();
    let bval: u16 = Demo::B.into();
    let cval: u16 = Demo::C.into();
    let deeval: u16 = Demo::DEE.into();
    assert_eq!(aval, 8_u16);
    assert_eq!(bval, 10);
    assert_eq!(cval, 7);
    assert_eq!(deeval, 999);

    let t: u16 = Demo::A.into();
    assert_eq!(t, 8);

    let t: Demo = 999.into();
    assert_eq!(t, Demo::DEE);
    assert!(t.is_recognized());

    let t: Demo = 6.into();
    let tval: u16 = t.into();
    assert_eq!(tval, 6);
    assert_eq!(t.get(), tval);
    assert!(!t.is_recognized());
}

#[test]
fn test_str_ops() {
    assert_eq!(Demo::A.to_str(), Some("A"));
    assert_eq!(Demo::B.to_str(), Some("B"));
    assert_eq!(format!("Hello {}", Demo::DEE), "Hello DEE");
    assert_eq!(format!("Hello {:?}", Demo::DEE), "Hello Demo(DEE)");

    let other: Demo = 33.into();
    assert_eq!(other.to_str(), None);
    assert_eq!(format!("Hello {other}"), "Hello 33");
    assert_eq!(format!("Hello {other:?}"), "Hello Demo(33)");

    assert_eq!(Demo::from_name("A"), Some(Demo::A));
    assert_eq!(Demo::from_name("Apricot"), None);
}
