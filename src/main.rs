mod data;

extern crate bitcoin;
extern crate num_cpus;

use std::{fs::{OpenOptions, File}, time::{Instant, Duration}, io::{BufRead, BufReader, Write}, path::Path, io};
use std::str::FromStr;
use std::sync::{Arc, mpsc};
use std::sync::mpsc::Sender;
use std::io::stdout;

use rustils::parse::boolean::string_to_bool;
use bloomfilter::Bloom;

use rand::{Rng};

use bitcoin::{Address, network::constants::Network, secp256k1::Secp256k1};
use bip39::{Mnemonic, Language, Seed, MnemonicType};
use bitcoin::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::secp256k1::All;
use hex::encode;
use libsecp256k1::{PublicKey, SecretKey};

use tiny_keccak::{Hasher, Keccak};
use tokio::task;

const FILE_CONFIG: &str = "confMnem.txt";

#[tokio::main]
async fn main() {
    println!("====================");
    println!("Find mnemonik v1.0.5");
    println!("====================");


    let count_cpu = num_cpus::get();
    //Чтение настроек, и если их нет создадим
    //-----------------------------------------------------------------
    let conf = match lines_from_file(&FILE_CONFIG) {
        Ok(text) => { text }
        Err(_) => {
            add_v_file(&FILE_CONFIG, data::get_conf_text().to_string());
            lines_from_file(&FILE_CONFIG).unwrap()
        }
    };

    let mut num_cores: i8 = first_word(&conf[0].to_string()).to_string().parse::<i8>().unwrap();
    let num_seed = first_word(&conf[1].to_string()).to_string();
    let mut all_variant = first_word(&conf[2].to_string()).to_string();
    let derivation1 = first_word(&conf[3].to_string()).to_string();
    let derivation0 = first_word(&conf[4].to_string()).to_string();
    let standart44 = first_word(&conf[5].to_string()).to_string();
    let standart49 = first_word(&conf[6].to_string()).to_string();
    let standart84 = first_word(&conf[7].to_string()).to_string();
    let eth44 = first_word(&conf[8].to_string()).to_string();
    //---------------------------------------------------------------------

    //база известных слов
    let file_content_lost = match lines_from_file("bip39_words.txt") {
        Ok(file) => { file }
        Err(_) => {
            let dockerfile = include_str!("bip39_words.txt");
            add_v_file("bip39_words.txt", dockerfile.to_string());
            lines_from_file("bip39_words.txt").expect("kakoyto_pizdec")
        }
    };

    //если список изменен включим прогон по всем комбинациям
    let inf = if file_content_lost.len() != 2048 && all_variant == "0".to_string() {
        all_variant = "1".to_string();
        "Bip39_words.txt edit -> on ALL VARIANT "
    } else { "" };

    let mut inf_test = "";
    let test = if num_cores == -1 {
        num_cores = 1;
        inf_test = "TEST ON";
        //создадим подсказку
        let info_test_user = "Для теста добавьте адреса в список адресов\n\
        16rNN6TA1s9nZgDyrJ4yTnoaRcYEZNdCAy\n\
        3PdgayHD7ciaur95kuGhAUMeLJV48shmko\n\
        bc1qwxyxtwknsqrjzpmx85ze7wyky9vmq5ukf3g0e5\n\
        или любой от этой мнемоники:\n\
        wool tourist shoe hurry galaxy grow okay element arrange submit solve adjust";
        add_v_file("info_setup_test.txt", info_test_user.to_string());
        "1".to_string()
    } else { "0".to_string() };

    println!("conf load:\n\
    -CPU CORE:{num_cores}/{count_cpu} {inf_test}\n\
    -SEED:{num_seed}\n\
    -ALL VARIANT:{} {inf}\n\
    -DERIVATION 0:{derivation0}\n\
    -DERIVATION 1:{derivation1}\n\
    -[m/44'/0'/0'/0/0]:{}\n\
    -[m/49'/0'/0'/0/0]:{}\n\
    -[m/84'/0'/0'/0/0]:{}\n\
    -[m/44'/60'/0'/0/0]:{}\n", string_to_bool(all_variant.clone()),
             string_to_bool(standart44.clone()), string_to_bool(standart49.clone()),
             string_to_bool(standart84.clone()), string_to_bool(eth44.clone()));

    //btc
    print!("LOAD ADDRESS BTC");
    let baza_btc = load_db("btc.txt");
    let len_btc = baza_btc.len();
    println!(":{}", len_btc);
    //eth
    print!("LOAD ADDRESS ETH");
    let baza_eth = load_db("eth.txt");
    let len_eth = baza_eth.len();
    println!(":{}",len_eth);


    //база для поиска
    let num_items = len_eth+len_btc;
    let fp_rate = 0.00000001;
    let mut database = Bloom::new_for_fp_rate(num_items, fp_rate);

    println!("LOAD BLOOM...");
    //
    for f in baza_btc {
        database.set(&f);
    }
    for f in baza_eth {
        database.set(&f);
    }

    println!("TOTAL ADDRESS LOAD:{:?}",num_items);
    println!("FIND WORD LOAD:{:?}\n", file_content_lost.len());

    // Если 0 значит тест изменим на 1
    // -----------------------------------------------------------
    let mut bench = "0".to_string();
    if num_cores == 0 {
        println!("--------------------------------");
        println!("        log mode 1 core");
        println!("--------------------------------");
        bench = "1".to_string();
        num_cores = 1;
    }
    // ------------------------------------------------------------
    let mut log = "0".to_string();
    if num_cores == -2 {
        println!("--------------------------------");
        println!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        println!("log and save to file mode 1 core");
        println!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        println!("--------------------------------");
        bench = "1".to_string();
        log = "1".to_string();
        num_cores = 1;
    }
    // ------------------------------------------------------------

    //дополнительные настройки упакуем в список
    let mut settings = vec![];
    settings.push(bench);
    settings.push(num_seed);
    settings.push(all_variant);
    settings.push(derivation1);
    settings.push(derivation0);
    settings.push(standart44);
    settings.push(standart49);
    settings.push(standart84);
    settings.push(test);
    settings.push(eth44);
    settings.push(log);

    //получать сообщения от потоков
    let (tx, rx) = mpsc::channel();
    let database = Arc::new(database);
    let file_content_lost = Arc::new(file_content_lost);
    let settings = Arc::new(settings);

    for _i in 0..num_cores {
        let database = database.clone();
        let tx = tx.clone();
        let file_content_lost = file_content_lost.clone();
        let settings = settings.clone();
        task::spawn_blocking(move || {
            process(&database, tx, &file_content_lost, &settings);
        });
    }

    //отображает инфу в однy строку(обновляемую)
    let backspace: char = 8u8 as char;
    let mut total_address: u64 = 0;
    let mut total_mnemonic: u64 = 0;
    let mut stdout = stdout();
    for received in rx {
        let list: Vec<&str> = received.split(",").collect();
        let mut speed = list[0].to_string().parse::<u64>().unwrap();
        let mnemonic = list[1].to_string().parse::<u64>().unwrap() * num_cores as u64;
        total_address = total_address + speed;
        total_mnemonic = total_mnemonic + mnemonic;
        speed = speed * num_cores as u64;
        print!("\r{}ADDRESS:{speed}/s || MNEMONIC:{mnemonic}/s || TOTAL:{total_address}/{total_mnemonic}  ", backspace);
        stdout.flush().unwrap();
    }
}


fn process(file_content: &Arc<Bloom<String>>, tx: Sender<String>, file_content_lost: &Arc<Vec<String>>, settings: &Arc<Vec<String>>) {
    let mut start = Instant::now();
    let mut speed: u32 = 0;
    let mut rng = rand::thread_rng();
    let secp: Secp256k1<All> = Secp256k1::new();
    let mut rnd_word = 0;

    let all_variant = settings[2].to_string().parse::<u8>().unwrap();
    let num_seed = settings[1].to_string().parse::<u8>().unwrap();
    let bench = string_to_bool(settings[0].to_string());
    let derivation1 = settings[3].to_string().parse::<usize>().unwrap();
    let derivation0 = settings[4].to_string().parse::<usize>().unwrap();
    let standart44 = string_to_bool(settings[5].to_string());
    let standart49 = string_to_bool(settings[6].to_string());
    let standart84 = string_to_bool(settings[7].to_string());
    let test = string_to_bool(settings[8].to_string());
    let eth44 = string_to_bool(settings[9].to_string());
    let log = string_to_bool(settings[10].to_string());

    let der_size = vec![derivation0, derivation1];
    let mut addresa = vec![];

    loop {
        let mut list_mnemonik = Vec::new();
        let mut mnemonic = "".to_string();

        if all_variant == 1 {
            for _i in 0..num_seed - 1 {
                let mut word = file_content_lost[rng.gen_range(0..file_content_lost.len())].to_string();
                word.push(' ');
                mnemonic.push_str(&word);
            }
            for i in 0..2048 {
                let mut mnemonic_test = String::from(&mnemonic);
                mnemonic_test.push_str(&data::WORDS_BIP39[i as usize].to_string());
                if Mnemonic::validate(&mnemonic_test, Language::English).is_ok() {
                    list_mnemonik.push(mnemonic_test);
                }
            }
        } else {
            list_mnemonik.push(get_seed(num_seed));
        }

        if test {
            list_mnemonik.push("wool tourist shoe hurry galaxy grow okay element arrange submit solve adjust".to_string());
        }

        rnd_word = rnd_word + 1;

        for m in list_mnemonik.iter() {
            let mn = Mnemonic::from_phrase(&m, Language::English).unwrap();
            let seed = Seed::new(&mn, "");
            for i in 0..=1 {
                for n in 0..=der_size[i] {
                    if standart44 {
                        addresa.push(address_from_seed_bip44(&seed.as_ref(), &secp, i, n))
                    }
                    if standart49 {
                        addresa.push(address_from_seed_bip49(&seed.as_ref(), &secp, i, n))
                    }
                    if standart84 {
                        addresa.push(address_from_seed_bip84(&seed, &secp, i, n))
                    }
                    if eth44 {
                        addresa.push(address_from_seed_eth(&seed.as_ref(), i, n));
                    }


                    for a in addresa.iter() {
                        if file_content.check(a) {
                            print_and_save(&m, &format!("{i}:{n}:[{a}]"));
                        }
                        if log {
                            add_v_file("log.txt", format!("\n[/{i}/{n}][{m}][{a}]"));
                        }
                        if bench {
                            println!("\n{m}");
                            println!("m/.../{i}/{n} {a}");
                        } else {
                            speed = speed + 1;
                            if start.elapsed() >= Duration::from_secs(1) {
                                tx.send(format!("{speed},{rnd_word}").to_string()).unwrap();
                                start = Instant::now();
                                speed = 0;
                                rnd_word = 0;
                            }
                        }
                    }
                    addresa.clear();
                }
            }
        }
    }
}

fn print_and_save(mnemonic: &String, addres: &String) {
    println!("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    println!("!!!!!!!!!!!!!!!!!!!!!!FOUND!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    println!("MNEMOMIC:{}", mnemonic);
    println!("ADDRESS:{}", addres);
    let s = format!("MNEMOMIC:{}\nADDRESS {}\n", mnemonic, addres);
    add_v_file("BOBLO.txt", s);
    println!("SAVE TO BOBLO.txt");
    println!("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
}

fn lines_from_file(filename: impl AsRef<Path>) -> io::Result<Vec<String>> {
    BufReader::new(File::open(filename)?).lines().collect()
}

fn add_v_file(name: &str, data: String) {
    OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(name)
        .expect("cannot open file")
        .write(data.as_bytes())
        .expect("write failed");
}

fn first_word(s: &String) -> &str {
    let bytes = s.as_bytes();
    for (i, &item) in bytes.iter().enumerate() {
        if item == b' ' {
            return &s[0..i];
        }
    }
    &s[..]
}


fn address_from_seed_bip44(seed: &[u8], secp: &Secp256k1<All>, d: usize, n: usize) -> String {
    let master_private_key = ExtendedPrivKey::new_master(Network::Bitcoin, &seed).unwrap();
    let path: DerivationPath = (format!("m/44'/0'/0'/{d}/{n}")).parse().unwrap();
    let child_priv = master_private_key.derive_priv(&secp, &path).unwrap();
    let child_pub = ExtendedPubKey::from_priv(&secp, &child_priv);
    let p = bitcoin::PublicKey::new(child_pub.public_key);
    let a: Address = Address::p2pkh(&p, Network::Bitcoin);
    return a.to_string();
}

fn address_from_seed_bip49(seed: &[u8], secp: &Secp256k1<All>, d: usize, n: usize) -> String {
    let master_private_key = ExtendedPrivKey::new_master(Network::Bitcoin, &seed).unwrap();
    let path: DerivationPath = (format!("m/49'/0'/0'/{d}/{n}")).parse().unwrap();
    let child_priv = master_private_key.derive_priv(&secp, &path).unwrap();
    let child_pub = ExtendedPubKey::from_priv(&secp, &child_priv);
    let p = bitcoin::PublicKey::new(child_pub.public_key);
    let a: Address = Address::p2shwpkh(&p, Network::Bitcoin).unwrap();
    return a.to_string();
}

fn address_from_seed_bip84(seed: &Seed, secp: &Secp256k1<All>, d: usize, n: usize) -> String {
    let master_private_key = ExtendedPrivKey::new_master(Network::Bitcoin, (&seed).as_ref()).unwrap();
    let path: DerivationPath = (format!("m/84'/0'/0'/{d}/{n}")).parse().unwrap();
    let child_priv = master_private_key.derive_priv(&secp, &path).unwrap();
    let child_pub = ExtendedPubKey::from_priv(&secp, &child_priv);
    let p = bitcoin::PublicKey::new(child_pub.public_key);
    let a: Address = Address::p2wpkh(&p, Network::Bitcoin).unwrap();
    return a.to_string();
}

fn address_from_seed_eth(seed: &[u8], d: usize, n: usize) -> String {
    let hdwallet = tiny_hderive::bip32::ExtendedPrivKey::derive(&seed, format!("m/44'/60'/0'/{d}").as_str()).unwrap();
    let account0 = hdwallet.child(tiny_hderive::bip44::ChildNumber::from_str(format!("{n}").as_str()).unwrap()).unwrap();

    let secret_key = SecretKey::parse(&account0.secret());
    let secret_key = match secret_key {
        Ok(sk) => sk,
        Err(_) => panic!("Failed to parse secret key"),
    };

    let public = PublicKey::from_secret_key(&secret_key);
    let public = &public.serialize()[1..65];

    let mut output = [0u8; 32];
    keccak_hash_in_place(public, &mut output);

    let _score = calc_score(&output);
    let addr = encode(&output[(output.len() - 20)..]);


    return addr.to_string();
}


fn get_seed(n: u8) -> String {
    match n {
        12 => Mnemonic::new(MnemonicType::Words12, Language::English).phrase().to_string(),
        15 => Mnemonic::new(MnemonicType::Words15, Language::English).phrase().to_string(),
        18 => Mnemonic::new(MnemonicType::Words18, Language::English).phrase().to_string(),
        21 => Mnemonic::new(MnemonicType::Words21, Language::English).phrase().to_string(),
        24 => Mnemonic::new(MnemonicType::Words24, Language::English).phrase().to_string(),
        _ => { "non".to_string() }
    }
}

//eth------------------------------------------------------------------
#[inline(always)]
fn keccak_hash_in_place(input: &[u8], output: &mut [u8; 32]) {
    let mut hasher = Keccak::v256();
    hasher.update(input);
    hasher.finalize(output);
}

const NIBBLE_MASK: u8 = 0x0F;
const SCORE_FOR_LEADING_ZERO: i32 = 100;

#[inline(always)]
fn calc_score(address: &[u8]) -> i32 {
    let mut score: i32 = 0;
    let mut has_reached_non_zero = false;

    for &byte in &address[(address.len() - 20)..] {
        score += score_nibble(byte >> 4, &mut has_reached_non_zero);
        score += score_nibble(byte & NIBBLE_MASK, &mut has_reached_non_zero);
    }

    score
}

#[inline(always)]
fn score_nibble(nibble: u8, has_reached_non_zero: &mut bool) -> i32 {
    let mut local_score = 0;

    if nibble == 0 && !*has_reached_non_zero {
        local_score += SCORE_FOR_LEADING_ZERO;
    } else if nibble != 0 {
        *has_reached_non_zero = true;
    }

    local_score
}


fn load_db(coin: &str) -> Vec<String> {
    let file_content = match lines_from_file(coin) {
        Ok(file) => { file }
        Err(_) => {
            let dockerfile = match coin {
                "btc.txt" => { include_str!("btc.txt") }
                "eth.txt" => { include_str!("eth.txt") }
                _ => { include_str!("btc.txt") }
            };
            add_v_file(coin, dockerfile.to_string());
            lines_from_file(coin).expect("kakoyto_pizdec")
        }
    };
    file_content
}