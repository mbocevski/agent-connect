//! Spike item 3: SAS from `epoch_authenticator` (SPEC §3.5, §11).

use agentconnect_spike_mls_xwing::*;
use openmls::prelude::*;
use openmls_libcrux_crypto::Provider;

#[test]
fn members_in_same_epoch_agree() {
    let mut m = group_of(3, &create_config());
    let sas: Vec<_> = m.iter().map(|x| sas_bytes(&x.group)).collect();
    assert!(sas.iter().all(|s| *s == sas[0]));

    // And again after an epoch change; the code changes with the epoch.
    let before = sas[0];
    let (head, rest) = m.split_at_mut(1);
    let a = &mut head[0];
    let bundle = a
        .group
        .self_update(&a.provider, &a.id.signer, LeafNodeParameters::default())
        .unwrap();
    a.group.merge_pending_commit(&a.provider).unwrap();
    let commit = wire(bundle.commit());
    for x in rest.iter_mut() {
        apply_commit(&mut x.group, &x.provider, &commit).unwrap();
    }
    let sas: Vec<_> = m.iter().map(|x| sas_bytes(&x.group)).collect();
    assert!(sas.iter().all(|s| *s == sas[0]));
    assert_ne!(sas[0], before);
    assert_eq!(sas_decimal(sas[0]).len(), "NNNN-NNNN-NNNN".len());
}

#[test]
fn relay_fork_produces_different_sas() {
    // A, B, C at epoch 1. A and B commit concurrently; a malicious relay
    // delivers A's commit to C and silently drops it for B (which merges its
    // own). All three are at epoch 2, but B's view differs.
    let mut m = group_of(3, &create_config());
    let mut commit = |i: usize| {
        let x = &mut m[i];
        let bundle = x
            .group
            .self_update(&x.provider, &x.id.signer, LeafNodeParameters::default())
            .unwrap();
        x.group.merge_pending_commit(&x.provider).unwrap();
        wire(bundle.commit())
    };
    let from_a = commit(0);
    let _from_b = commit(1);
    let c = &mut m[2];
    apply_commit(&mut c.group, &c.provider, &from_a).unwrap();

    let epochs: Vec<_> = m.iter().map(|x| x.group.epoch()).collect();
    assert!(epochs.iter().all(|e| *e == epochs[0]));
    let [a, b, c] = [0, 1, 2].map(|i| sas_bytes(&m[i].group));
    assert_eq!(a, c);
    assert_ne!(a, b);
}

#[test]
fn mitm_with_two_groups_produces_different_sas() {
    // SPEC §14.4: an attacker runs two groups with the same group_id, one
    // towards A and one towards B. Same epoch number, different codes.
    let config = create_config();
    let gid = GroupId::from_slice(b"same-group-id-16");
    let pair = |name_a: &str, name_b: &str| {
        let pa = Provider::new().unwrap();
        let pb = Provider::new().unwrap();
        let a = Identity::new(name_a, &pa);
        let b = Identity::new(name_b, &pb);
        let mut ga =
            MlsGroup::new_with_group_id(&pa, &a.signer, &config, gid.clone(), a.credential.clone())
                .unwrap();
        let kp = b.key_package(&pb, ac_capabilities(), instance_cert_ext(b"{}"));
        let (_, w, _) = ga.add_members(&pa, &a.signer, &[kp]).unwrap();
        ga.merge_pending_commit(&pa).unwrap();
        let gb = join(&pb, &wire(&w)).unwrap();
        assert_eq!(sas_bytes(&ga), sas_bytes(&gb));
        (ga, gb)
    };
    let (real_a, _attacker_as_b) = pair("ac:v0:alice", "ac:v0:bob");
    let (_attacker_as_a, real_b) = pair("ac:v0:alice", "ac:v0:bob");
    assert_eq!(real_a.epoch(), real_b.epoch());
    assert_ne!(sas_bytes(&real_a), sas_bytes(&real_b));
}

#[test]
fn sas_decimal_vector() {
    // 48 bits, all ones: each 13-bit group is 8191, plus 1000.
    assert_eq!(sas_decimal([0xFF; 6]), "9191-9191-9191");
    assert_eq!(sas_decimal([0; 6]), "1000-1000-1000");
}
