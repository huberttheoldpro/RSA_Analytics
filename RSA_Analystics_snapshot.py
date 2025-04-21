#  Copyright © 2025 Hubert Gaszow. All rights reserved.

from concurrent.futures import ThreadPoolExecutor, as_completed
from math import gcd, prod, log2, ceil
import multiprocessing
from collections import Counter
import random
import tempfile
import time
import traceback
import json
import argparse
import hashlib
import os
from datetime import datetime

terminate == False 

def missing_library_installer(terminate):
    pycryptodome = False
    try:
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        pycryptodome = True
    except ImportError:
        print("PyCryptodome is missing or not accessible, attempting to install pycryptodome now")
        os.system("pip install pycryptodome")
        print("Reattempting import of pycryptodome features")
        try:
            from Crypto.PublicKey import RSA
            from Crypto.Cipher import PKCS1_OAEP
            pycryptodome = True
        except ImportError:
            print("Import failed. Terminating.")
            terminate = True
    numpy = False
    try:
        import numpy as np
        numpy = True
    except ImportError:
        print("Numpy is missing or not accessible, attempting to install numpy")
        os.system("pip install numpy")
        print("Reattempting to import numpy now")
        try:
            import numpy as np
            numpy = True
        except ImportError:
            print("Import failed. The script will now terminate.")
            terminate = True
    sklearn_installed = False
    try:
        import sklearn
        sklearn_installed = True
    except ImportError:
        print("scikit-learn is missing, attempting to install scikit-learn")
        os.system("pip install scikit-learn")
        print("Reattempting to import scikit-learn now")
        try:
            import sklearn
            sklearn_installed = True
        except ImportError:
            print("Import failed. The script will now terminate.")
            terminate = True
    sympy_installed = False
    try:
        import sympy
        sympy_installed = True
    except ImportError:
        print("sympy is missing, attempting to install sympy")
        os.system("pip install sympy")
        print("Reattempting to import sympy now")
        try:
            import sympy
            sympy_installed = True
        except ImportError:
            print("Import failed. The script will now terminate.")
            terminate = True
    pandas_installed = False
    try:
        import pandas as pd
        pandas_installed = True
    except ImportError:
        print("pandas is missing, attempting to install pandas")
        os.system("pip install pandas")
        print("Reattempting to import pandas now")
        try:
            import pandas as pd
            pandas_installed = True
        except ImportError:
            print("Import failed. The script will now terminate.")
            terminate = True
    matplotlib_installed = False
    try:
        import matplotlib.pyplot as plt
        matplotlib_installed = True
    except ImportError:
        print("matplotlib is missing, attempting to install matplotlib")
        os.system("pip install matplotlib")
        print("Reattempting to import matplotlib now")
        try:
            import matplotlib.pyplot as plt
            matplotlib_installed = True
        except ImportError:
            print("Import failed. The script will now terminate.")
            terminate = True
    seaborn_installed = False
    try:
        import seaborn as sns
        seaborn_installed = True
    except ImportError:
        print("seaborn is missing, attempting to install seaborn")
        os.system("pip install seaborn")
        print("Reattempting to import seaborn now")
        try:
            import seaborn as sns
            seaborn_installed = True
        except ImportError:
            print("Import failed. The script will now terminate.")
            terminate = True
    cryptography_installed = False
    try:
        import cryptography
        cryptography_installed = True
    except ImportError:
        print("cryptography is missing, attempting to install cryptography")
        os.system("pip install cryptography")
        print("Reattempting to import cryptography now")
        try:
            import cryptography
            cryptography_installed = True
        except ImportError:
            print("Import failed. The script will now terminate.")
            terminate = True
    return terminate






LOGFILE = "/root/rsa_analysis_log.txt"
JSONFILE = "/root/rsa_analysis_metadata.json"
KEY_SIZE = 1024
NUM_SAMPLES = 50
KNOWN_BAD_PRIMES = [3, 5, 7, 11]
MAX_LOG_SIZE = 10 * 1024 * 1024  #10MB log rotation

def log(msg):
    print(msg)
    try:
        if os.path.exists(LOGFILE) and os.path.getsize(LOGFILE) > MAX_LOG_SIZE:
            os.rename(LOGFILE, LOGFILE + "." + datetime.now().strftime("%Y%m%d%H%M%S"))
        with open(LOGFILE, "a") as f:
            f.write(msg + "\n")
    except Exception as e:
        print(f"Error writing to log file: {e}")
        print(traceback.format_exc())

def generate_sample_data(num_samples=NUM_SAMPLES, key_size=KEY_SIZE):
    keys = []
    ciphertexts = []
    file_sizes = []
    plaintext_sizes = []
    e_values = []
    plaintext = b'This is a test message.'
    temp_files = []  #temp file trace

    try:
        for idx in range(num_samples):
            key = RSA.generate(key_size)
            cipher = PKCS1_OAEP.new(key.publickey())
            ct = cipher.encrypt(plaintext)
            keys.append(key.publickey().n)
            ciphertexts.append(int.from_bytes(ct, byteorder='big'))
            e_values.append(key.publickey().e)

            pt_file = tempfile.NamedTemporaryFile(delete=False)
            ct_file = tempfile.NamedTemporaryFile(delete=False)

            try:
                pt_file.write(plaintext)
                pt_file.flush()
                ct_file.write(ct)
                ct_file.flush()

                pt_filename = pt_file.name
                ct_filename = ct_file.name

                plaintext_sizes.append(os.path.getsize(pt_filename))
                file_sizes.append(os.path.getsize(ct_filename))

                temp_files.append(pt_filename)
                temp_files.append(ct_filename)

            finally:
                pt_file.close() 
                ct_file.close()  

    except Exception as e:
        log(f"Error generating sample data: {e}")
        print(traceback.format_exc())
    finally:
        for filename in temp_files:
            try:
                os.remove(filename)
            except Exception as e:
                log(f"Error removing temp file {filename}: {e}")

    return (
        np.array(keys),
        np.array(ciphertexts),
        np.array(file_sizes),        #ciphertext
        np.array(e_values),
        np.array(plaintext_sizes)    #plaintext
    )

def load_keys_from_file(filename):
    try:
        with open(filename, 'r') as f:
            keys = [int(line.strip()) for line in f]
        return np.array(keys)
    except Exception as e:
        log(f"Error loading keys from {filename}: {e}")
        return None

def gcd_worker(args):
    i, j, keys = args
    try:
        g = gcd(keys[i], keys[j])
        if g != 1 and g != keys[i] and g != keys[j]:
            return f"Shared factor found between key {i} and key {j}: {g}"
    except Exception as e:
        return f"GCD error for keys {i} and {j}: {e}"
    return None

def gcd_analysis(keys, findings, max_workers=1):
    tasks = [(i, j, keys) for i in range(len(keys)) for j in range(i+1, len(keys))]
    with multiprocessing.Pool(processes=max_workers) as pool:
        for result in pool.imap_unordered(gcd_worker, tasks):
            if result:
                log(result)
                findings['gcd'].append(result)

def common_multiple_analysis(keys, findings, max_multiple=500, max_workers=1):
    tasks = [(i, j, keys, max_multiple) for i in range(len(keys)) for j in range(i+1, len(keys))]
    with multiprocessing.Pool(processes=max_workers) as pool:
        for result in pool.imap_unordered(common_multiple_worker, tasks):
            if result:
                log(result)
                findings['common_multiples'].append(result)

def batch_gcd_worker(pair):
    i, j, moduli = pair
    try:
        g = gcd(moduli[i], moduli[j])
        if g > 1:
            return g, i, j
    except Exception as e:
        return None
    return None

def batch_gcd_attack(moduli, findings):
    n = len(moduli)
    tasks = [(i, j, moduli) for i in range(n) for j in range(i + 1, n)]
    with multiprocessing.Pool() as pool:
        for result in pool.imap_unordered(batch_gcd_worker, tasks):
            if result:
                g, i, j = result
                msg = f"Batch GCD: Shared factor {g} between moduli {i} and {j}"
                log(msg)
                findings['batch_gcd'].append(msg)

def file_size_clustering(file_sizes, findings, n_clusters=3):
    try:
        file_sizes = file_sizes.reshape(-1, 1)
        kmeans = KMeans(n_clusters=n_clusters, random_state=0, n_init=10)
        labels = kmeans.fit_predict(file_sizes)
        for i, label in enumerate(labels):
            msg = f"File {i}: Size {file_sizes[i][0]}, Cluster {label}"
            log(msg)
            findings['file_size_clusters'].append(msg)
        findings['file_size_labels'] = labels.tolist()
    except Exception as e:
        log(f"File size clustering error: {e}")

def extract_randomness_features(keys, ciphertexts):
    features = []
    try:
        for k, c in zip(keys, ciphertexts):
            k_bin = bin(k)[2:]
            c_bin = bin(c)[2:]
            features.append([
                len(k_bin),
                k_bin.count('1')/len(k_bin),
                len(c_bin),
                c_bin.count('1')/len(c_bin),
            ])
    except Exception as e:
        log(f"Error extracting randomness features: {e}")
        return None
    return np.array(features)

def randomness_clustering(features, findings, n_clusters=3):
    try:
        kmeans = KMeans(n_clusters=n_clusters, random_state=0, n_init=10)
        labels = kmeans.fit_predict(features)
        for i, label in enumerate(labels):
            msg = f"Sample {i}: Cluster {label}, Features: {features[i]}"
            log(msg)
            findings['randomness_clusters'].append(msg)
        findings['randomness_labels'] = labels.tolist()
    except Exception as e:
        log(f"Randomness clustering error: {e}")

def key_bit_pattern_analysis(keys, findings):
    try:
        for i, key in enumerate(keys):
            bin_k = bin(key)[2:]
            msg = f"Key {i}: starts with {bin_k[:10]}, ends with {bin_k[-10:]}"
            log(msg)
            findings['key_bit_patterns'].append(msg)
    except Exception as e:
        log(f"Key bit pattern analysis error: {e}")

def shannon_entropy(binary_string):
    counts = Counter(binary_string)
    total = len(binary_string)
    return -sum((c/total) * log2(c/total) for c in counts.values())

def entropy_analysis(ciphertexts, findings):
    try:
        binary_ciphertexts = [bin(c)[2:] for c in ciphertexts]
        entropies = np.array([shannon_entropy(bc) for bc in binary_ciphertexts])
        
        for i, entropy in enumerate(entropies):
            msg = f"Ciphertext {i}: Entropy = {entropy:.4f}"
            log(msg)
            findings['entropy'].append(msg)
        findings['entropy_values'] = entropies.tolist()
    except Exception as e:
        log(f"Entropy analysis error: {e}")

def pca_visualization(features, labels, findings, args):
    try:
        pca = PCA(n_components=2)
        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(features)
        reduced = pca.fit_transform(scaled_features)

        findings['pca_components'] = pca.components_.tolist()
        findings['pca_explained_variance'] = pca.explained_variance_ratio_.tolist()
        
        findings['pca_axes_labels'] = {
            'PC1': 'Weighted combination of key and ciphertext bit lengths and densities',
            'PC2': 'Another weighted combination of key and ciphertext bit lengths and densities'
        }
        for i, point in enumerate(reduced):
            msg = f"Sample {i}: PC1={point[0]:.3f}, PC2={point[1]:.3f}"
            log(msg)
            findings['pca'].append(msg)
        findings['pca_points'] = reduced.tolist()

        if not args.no_visualization:
            plt.figure(figsize=(8, 6))
            if labels is not None:
                plt.scatter(reduced[:, 0], reduced[:, 1], c=labels, cmap='viridis')
            else:
                plt.scatter(reduced[:, 0], reduced[:, 1])
            plt.xlabel("PC1 (Explained Variance: {:.2f}%)".format(pca.explained_variance_ratio_[0] * 100))
            plt.ylabel("PC2 (Explained Variance: {:.2f}%)".format(pca.explained_variance_ratio_[1] * 100))
            plt.title("PCA Visualization of RSA Key Features")
            for i in range(len(reduced)):
                plt.annotate(str(i), xy=(reduced[i, 0], reduced[i, 1]))
            plot_filename = f"/root/pca_plot_{time.time()}.png"
            plt.savefig(plot_filename)
            findings['pca_plot_filename'] = plot_filename
            plt.close()

    except Exception as e:
        log(f"PCA visualization error: {e}")

def modulus_difference_check(keys, findings):
    try:
        for i in range(len(keys)):
            for j in range(i+1, len(keys)):
                diff = abs(keys[i] - keys[j])
                if diff < 2**16:
                    msg = f"Moduli {i} and {j} are very close: diff = {diff}"
                    log(msg)
                    findings['modulus_diffs'].append(msg)
    except Exception as e:
        log(f"Modulus difference check error: {e}")

def e_value_analysis(e_values, findings):
    try:
        counts = Counter(e_values)
        for e, count in counts.items():
            if count > 1:
                msg = f"e value {e} is used {count} times"
                log(msg)
                findings['e_value_reuse'].append(msg)
        findings['e_values'] = e_values.tolist()
    except Exception as e:
        log(f"E value analysis error: {e}")

def small_prime_factor_check(keys, findings, bound=10000):
    try:
        small_primes = list(primerange(2, bound))
        for i, n in enumerate(keys):
            for p in small_primes:
                if n % p == 0:
                    msg = f"Key {i}: divisible by small prime {p}"
                    log(msg)
                    findings['small_prime_factors'].append(msg)
                    break
    except Exception as e:
        log(f"Small prime factor check error: {e}")

def modulus_reuse_check(keys, findings):
    try:
        seen = Counter(keys)
        for n, count in seen.items():
            if count > 1:
                msg = f"Modulus reused {count} times: n = {n}"
                log(msg)
                findings['modulus_reuse'].append(msg)
                try:
                    factors = factorint(n)
                    msg = f"  Factors of reused modulus: {factors}"
                    log(msg)
                    findings['modulus_reuse_factors'][n] = factors
                except Exception as e:
                    log(f"  Error factoring reused modulus: {e}")
    except Exception as e:
        log(f"Modulus reuse check error: {e}")

def key_length_distribution(keys, findings):
    try:
        bit_lengths = [key.bit_length() for key in keys]
        for i, bl in enumerate(bit_lengths):
            msg = f"Key {i} bit length: {bl}"
            log(msg)
            findings['key_lengths'].append(msg)
        findings['bit_lengths'] = bit_lengths
    except Exception as e:
        log(f"Key length distribution error: {e}")

def hamming_distance(a, b):
    return bin(a ^ b).count('1')

def ciphertext_hamming_analysis(ciphertexts, findings):
    try:
        for i in range(len(ciphertexts)):
            distances = np.array([hamming_distance(ciphertexts[i], ciphertexts[j]) for j in range(i+1, len(ciphertexts))])
            for j, d in enumerate(distances):
                if d < 100:
                    msg = f"Low Hamming distance between ciphertext {i} and {i+j+1}: {d}"
                    log(msg)
                    findings['hamming'].append(msg)
    except Exception as e:
        log(f"Ciphertext Hamming analysis error: {e}")

def timed_key_generation(findings, num_samples=NUM_SAMPLES, key_size=KEY_SIZE):
    try:
        times = []
        for _ in range(num_samples):
            start = time.time()
            RSA.generate(key_size)
            times.append(time.time() - start)
        avg = sum(times)/len(times)
        msg = f"Average key gen time: {avg:.4f}s"
        log(msg)
        findings['keygen_time'] = avg
    except Exception as e:
        log(f"Timed key generation error: {e}")

def prime_factor_distribution(keys, findings):
    try:
        all_prime_factors = []
        for i, key in enumerate(keys):
            factors = factorint(key)
            all_prime_factors.append(factors)
            msg = f"Key {i}: Prime Factors = {factors}"
            log(msg)
            findings['prime_factor_analysis'].append(msg)
        findings['prime_factor_distribution'] = all_prime_factors
    except Exception as e:
        log(f"Prime factor distribution error: {e}")

def outlier_detection(ciphertexts, findings):
    try:
        ciphertexts_array = np.array(ciphertexts).reshape(-1, 1)
        scaler = StandardScaler()
        scaled_ciphertexts = scaler.fit_transform(ciphertexts_array)
        model = IsolationForest(n_estimators=100, contamination='auto', random_state=42)
        model.fit(scaled_ciphertexts)
        outlier_predictions = model.predict(scaled_ciphertexts)

        outliers = []
        for i, prediction in enumerate(outlier_predictions):
            if prediction == -1:
                outliers.append(i)
                msg = f"Ciphertext {i} detected as an outlier"
                log(msg)
                findings['outliers'].append(msg)
        findings['outlier_indices'] = outliers
    except Exception as e:
        log(f"Outlier detection error: {e}")

def check_known_bad_primes(keys, findings):
    try:
        for i, key in enumerate(keys):
            for prime in KNOWN_BAD_PRIMES:
                if key % prime == 0:
                    msg = f"Key {i} divisible by known bad prime: {prime}"
                    log(msg)
                    findings['known_bad_primes'].append(msg)
    except Exception as e:
        log(f"Known bad primes check error: {e}")

def fingerprint_modulus(n):
    try:
        return hashlib.sha256(str(n).encode()).hexdigest()
    except Exception as e:
        log(f"Error generating fingerprint for modulus {n}: {e}")
        return None

def parse_rsa_cert(cert_path, findings):
    try:
        with open(cert_path, 'rb') as f:
            cert_data = f.read()

        try:
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        except ValueError:
            try:
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
            except ValueError as e:
                msg = f"Error loading certificate from {cert_path}: Could not decode PEM or DER format. {e}"
                log(msg)
                findings['parsed_certs'].append(msg)
                return

        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            modulus = public_key.n
            public_exponent = public_key.e

            msg = f"Certificate at {cert_path}: Modulus = {modulus}, Public Exponent = {public_exponent}"
            log(msg)
            findings['parsed_certs'].append(msg)
        else:
            msg = f"Certificate at {cert_path}: Not an RSA certificate"
            log(msg)
            findings['parsed_certs'].append(msg)

    except FileNotFoundError:
        msg = f"Error parsing certificate {cert_path}: File not found."
        log(msg)
        findings['parsed_certs'].append(msg)
    except Exception as e:
        msg = f"Error parsing certificate {cert_path}: {e}"
        log(msg)
        findings['parsed_certs'].append(msg)


def run_all_checks(args):
    findings = {
        'gcd': [],
        'common_multiples': [],
        'batch_gcd': [],
        'file_size_clusters': [],
        'file_size_labels': [],
        'randomness_clusters': [],
        'randomness_labels': [],
        'key_bit_patterns': [],
        'entropy': [],
        'entropy_values': [],
        'pca': [],
        'pca_components': [],
        'pca_explained_variance': [],
        'pca_axes_labels': {},
        'pca_points': [],
        'pca_plot_filename': None,
        'modulus_diffs': [],
        'e_value_reuse': [],
        'e_values': [],
        'small_prime_factors': [],
        'modulus_reuse': [],
        'modulus_reuse_factors': {},
        'key_lengths': [],
        'bit_lengths': [],
        'hamming': [],
        'keygen_time': None,
        'file_size_stats': None,
        'correlation_matrix': None,
        'prime_factor_distribution': None,
        'prime_factor_analysis': [],
        'outliers': [],
        'outlier_indices': [],
        'known_bad_primes': [],
        'parsed_certs': [],
        'timestamp': time.time(),
        'timestamp_human': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time())),
        'ciphertext_collisions': [],
        'modulus_fingerprints': [],
        'ciphertext_fingerprints': [],
    }

    keys, ciphertexts, file_sizes, e_values, plaintext_sizes = generate_sample_data()

    if not (args.quick or args.entropy_only):
        features = extract_randomness_features(keys, ciphertexts)
        pca_labels = None
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = []
            futures.append(executor.submit(gcd_analysis, keys, findings, args.threads))
            futures.append(executor.submit(pca_visualization, features, pca_labels, findings, args))
            futures.append(executor.submit(common_multiple_analysis, keys, findings, 500, args.threads))
            futures.append(executor.submit(batch_gcd_attack, keys, findings))
            futures.append(executor.submit(file_size_clustering, file_sizes, findings))
            futures.append(executor.submit(modulus_difference_check, keys, findings))
            futures.append(executor.submit(small_prime_factor_check, keys, findings))
            futures.append(executor.submit(modulus_reuse_check, keys, findings))
            futures.append(executor.submit(key_length_distribution, keys, findings))
            futures.append(executor.submit(ciphertext_hamming_analysis, ciphertexts, findings))
            futures.append(executor.submit(e_value_analysis, e_values, findings))
            futures.append(executor.submit(prime_factor_distribution, keys, findings))
            futures.append(executor.submit(check_known_bad_primes, keys, findings))
            for f in as_completed(futures):
                pass

        file_size_stats = {
            'mean': np.mean(file_sizes),
            'median': np.median(file_sizes),
            'std': np.std(file_sizes),
            'min': np.min(file_sizes),
            'max': np.max(file_sizes)
        }
        findings['file_size_stats'] = file_size_stats

        df = pd.DataFrame({
            'key_lengths': [len(bin(k)[2:]) for k in keys],
            'file_sizes': file_sizes.flatten(),
            'plaintext_sizes': plaintext_sizes.flatten(),
            'entropies': findings.get('entropy_values', []),
            'e_values': e_values
        })

        try:
            correlation_matrix = df.corr()
            findings['correlation_matrix'] = correlation_matrix.to_dict()
            if args.save_csv:
                df.to_csv('/root/rsa_analysis_metadata.csv', index=False)
        except Exception as e:
            log(f"Error during dataframe operations: {e}")
            log(traceback.format_exc())

    if not args.quick:
        features = extract_randomness_features(keys, ciphertexts)
        if features is not None:
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = []
                futures.append(executor.submit(randomness_clustering, features, findings))
                futures.append(executor.submit(key_bit_pattern_analysis, keys, findings))
                pca_labels = findings.get('randomness_labels') if 'randomness_labels' in findings else None
                futures.append(executor.submit(pca_visualization, features, pca_labels, findings))
                futures.append(executor.submit(outlier_detection, ciphertexts, findings))
                for f in as_completed(futures):
                    pass

    if args.entropy_only or not args.quick:
        entropy_analysis(ciphertexts, findings)

    if not (args.quick or args.entropy_only):
        timed_key_generation(findings)

    ciphertext_counts = Counter(ciphertexts)
    for ct, count in ciphertext_counts.items():
        if count > 1:
            indices = [i for i, x in enumerate(ciphertexts) if x == ct]
            msg = f"Ciphertext collision: {ct} appears {count} times at indices {indices}"
            log(msg)
            findings['ciphertext_collisions'].append(msg)

    for i, n in enumerate(keys):
        fingerprint = fingerprint_modulus(n)
        msg = f"Modulus {i} fingerprint: {fingerprint}"
        log(msg)
        findings['modulus_fingerprints'].append(msg)

    for i, c in enumerate(ciphertexts):
        try:
            fingerprint = hashlib.sha256(str(c).encode()).hexdigest()
            findings['ciphertext_fingerprints'].append(fingerprint)
        except Exception as e:
            log(f"Error fingerprinting ciphertext {i}: {e}")

    if args.cert_path:
        parse_rsa_cert(args.cert_path, findings)

    return findings

if __name__ == "__main__":
    default_workers = multiprocessing.cpu_count()
    parser = argparse.ArgumentParser(description='Analyze RSA keys for patterns.')
    parser.add_argument('--quick', action='store_true', help='Run only a quick analysis (skips some checks).')
    parser.add_argument('--deep', action='store_true', help='Run all checks (default).')
    parser.add_argument('--entropy-only', action='store_true', help='Run only entropy analysis.')
    parser.add_argument('--cert-path', type=str, help='Path to a real-world RSA certificate (PEM or DER).')
    parser.add_argument('--no-visualization', action='store_true', help='Disable PCA visualization plots.')
    parser.add_argument('--key-file', type=str, help='Path to a file containing a list of RSA moduli (one per line).')
    parser.add_argument('--save-csv', action='store_true', help='Save metadata to CSV file.')
    parser.add_argument('--threads', type=int, default=default_workers, help=f'Number of threads to use (default: number of CPU cores = {default_workers})')
    args = parser.parse_args()

    log("=== RSA Pattern Analysis Started ===")
    try:
        while True:
            findings = run_all_checks(args)
            try:
                with open(JSONFILE, "a") as jf:
                    json.dump(findings, jf)
                    jf.write("\n")
            except Exception as e:
                log(f"Error writing to JSON file: {e}")
            log("Batch complete. Sleeping 3 seconds...\n")
            time.sleep(3)
    except KeyboardInterrupt:
        log("=== RSA Pattern Analysis Stopped ===")
