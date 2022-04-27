
use libsecp256k1::curve::{ECMultContext, ECMultGenContext, Scalar};
use libsecp256k1::{Message, PublicKey, SecretKey};

fn main() {
    // 公私钥对生成
    let context = ECMultGenContext::new_boxed();
    let sk = SecretKey::parse(&[10u8; 32]).unwrap();
    let pk = PublicKey::from_secret_key_with_context(&sk, &context);
    println!("sk:{:x}\npk:{:?}", sk, pk.serialize());

    // 签名
    let message = Message::parse(&[10u8; 32]);
    let mut nonce = Scalar::default();
    nonce.set_b32(&[0x22; 32]); // TODO: randomnize
    let (r, s, v) = context.sign_raw(&sk.into(), &message.0, &nonce).unwrap();
    println!("r:{:?}\n s:{:?}\n v:{:?}", r.b32(), s.b32(), v+27); // For solidity ecrecover

    // 签名验证
    let context1 = ECMultContext::new_boxed();
    let ok = context1.verify_raw(&r, &s, &pk.into(), &message.0);
    println!("{}", ok);
}
