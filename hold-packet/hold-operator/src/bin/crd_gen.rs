use kube::CustomResourceExt;
use hold_operator::stz::ScaleToZero;

fn main() {
    let crd = ScaleToZero::crd();
    let yaml = serde_yaml::to_string(&crd).expect("failed to serialize CRD");
    print!("{yaml}");
}
