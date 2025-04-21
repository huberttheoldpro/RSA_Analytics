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

terminate = False

def missing_library_installer(terminate):
    flask = False
    try:
        from flask import Flask, render_template, request
    except ImportError:
        print("PyCryptodome is missing or not accessible, attempting to install pycryptodome now")
        os.system("pip install flask")
        print("Reattempting import of flask features")
        try:
            from flask import Flask, render_template, request
            flask = True
        except ImportError:
            print("Import failed. Terminating.")
            terminate = True
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


def run_flask(args, keys, ciphertexts, file_sizes, e_values, plaintext_sizes, findings):
    from flask import Flask, render_template, request
    import pandas as pd
    import io
    import base64
    import matplotlib.pyplot as plt
    import seaborn as sns
    import numpy as np
    from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
    import json
    import os

    app = Flask(__name__)

    global last_updated
    last_updated = None
    JSON_FILE = "/root/rsa_analysis_metadata.json"

    index_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>RSA Analysis Visualization</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #333; }
            .plot-container { border: 1px solid #ddd; margin-bottom: 20px; padding: 10px; }
            .plot-image { max-width: 100%; height: auto; }
            .data-selection { margin-bottom: 20px; }
            label { display: block; margin-bottom: 5px; }
            .timestamp { font-size: small; color: gray; }
        </style>
        <meta http-equiv="refresh" content="30">
    </head>
    <body>
        <h1>RSA Analysis Visualization</h1>
        <p class="timestamp">Last updated: {{ last_updated }}</p>

        <div class="data-selection">
            <form method="post" action="/">
                <label>Select Data to Visualize:</label>
                {% for data_id in available_data %}
                    <div>
                        <input type="checkbox" id="{{ data_id }}" name="data_selection" value="{{ data_id }}" {% if data_id in selected_data %}checked{% endif %}>
                        <label for="{{ data_id }}">{{ data_id.capitalize() }}</label>
                    </div>
                {% endfor %}
                <button type="submit">Update Plots</button>
            </form>
        </div>

        {% if plots %}
            {% for plot in plots %}
                <div class="plot-container">
                    <h2>{{ plot.title }}</h2>
                    {% if plot.image %}
                        <img src="data:image/png;base64,{{ plot.image }}" alt="Plot of {{ plot.title }}" class="plot-image">
                    {% elif plot.error %}
                        <p style="color: red;">Error: {{ plot.error }}</p>
                    {% else %}
                        <p>No data to display for {{ plot.title }}.</p>
                    {% endif %}
                </div>
            {% endfor %}
        {% else %}
            <p>No plots to display. Select data and click 'Update Plots'.</p>
        {% endif %}

        {% if findings %}
            <h2>Findings:</h2>
            <ul>
                {% for key, value in findings.items() %}
                    <li><strong>{{ key }}:</strong> {{ value }}</li>
                {% endfor %}
            </ul>
        {% endif %}

    </body>
    </html>
    """

    def render_template(template_name, **context):
        if template_name == "index.html":
            s = index_html
            for key, value in context.items():
                s = s.replace("{{ " + key + " }}", str(value))
                if isinstance(value, list):
                    s = s.replace("{{ " + key + "|length }}", str(len(value)))
            if "{% for data_id in available_data %}" in s:
                loop_content = ""
                start = s.find("{% for data_id in available_data %}")
                end = s.find("{% endfor %}")
                if start != -1 and end != -1:
                    template = s[
                        start
                        + len("{% for data_id in available_data %}") : end
                    ]
                    for data_id in context.get("available_data", []):
                        temp = template.replace("{{ data_id }}", str(data_id))
                        temp = temp.replace(
                            "{{ data_id|capitalize }}", str(data_id).capitalize()
                        )
                        if data_id in context.get("selected_data", []):
                            temp = temp.replace(
                                "{{ 'checked' if data_id in selected_data else '' }}",
                                "checked",
                            )
                        else:
                            temp = temp.replace(
                                "{{ 'checked' if data_id in selected_data else '' }}",
                                "",
                            )
                        loop_content += temp
                    s = s[:start] + loop_content + s[end + len("{% endfor %}") :]

            return s
        else:
            return f"Template not found: {template_name}"

    def create_flask_app(
        keys_data,
        ciphertexts_data,
        file_sizes_data,
        e_values_data,
        plaintext_sizes_data,
        findings_data,
        update_interval=60,
    ):
        global keys, ciphertexts, file_sizes, e_values, plaintext_sizes, findings, last_updated
        keys, ciphertexts, file_sizes, e_values, plaintext_sizes, findings = (
            keys_data,
            ciphertexts_data,
            file_sizes_data,
            e_values_data,
            plaintext_sizes_data,
            findings_data,
        )
        last_updated = time.strftime("%Y-%m-%d %H:%M:%S")
        app = Flask(__name__)
        app.config["TEMPLATES_AUTO_RELOAD"] = True

        @app.route("/", methods=["GET", "POST"])
        def index():
            plots = []
            selected_data = {}

            if request.method == "POST":
                selected_data = request.form.getlist("data_selection")
            else:
                selected_data = [
                    "keys",
                    "ciphertexts",
                    "file_sizes",
                    "e_values",
                    "plaintext_sizes",
                ]

            available_data = {
                "keys": {"data": keys, "label": "Keys"},
                "ciphertexts": {"data": ciphertexts, "label": "Ciphertexts"},
                "file_sizes": {"data": file_sizes, "label": "File Sizes"},
                "e_values": {"data": e_values, "label": "E Values"},
                "plaintext_sizes": {"data": plaintext_sizes, "label": "Plaintext Sizes"},
            }

            for data_id in selected_data:
                if data_id in available_data:
                    data = available_data[data_id]["data"]
                    label = available_data[data_id]["label"]

                    if data is not None and len(data) > 0:
                        try:
                            fig, ax = plt.subplots(figsize=(8, 6))
                            sns.histplot(data, kde=True, ax=ax)
                            ax.set_title(f"Distribution of {label}")
                            ax.set_xlabel(label)
                            ax.set_ylabel("Frequency")

                            canvas = FigureCanvas(fig)
                            img_data = io.BytesIO()
                            fig.savefig(img_data, format="png")
                            img_data.seek(0)

                            plot_url = base64.b64encode(img_data.read()).decode("utf-8")
                            plots.append({"title": label, "image": plot_url})

                            plt.close(fig)
                        except Exception as e:
                            plots.append(
                                {
                                    "title": label,
                                    "image": None,
                                    "error": f"Plotting error: {e}",
                                }
                            )
                    else:
                        plots.append(
                            {
                                "title": label,
                                "image": None,
                                "error": "Data is empty or not available.",
                            }
                        )

            return render_template(
                "index.html",
                plots=plots,
                selected_data=selected_data,
                available_data=available_data.keys(),
                findings=findings,
                last_updated=last_updated,
            )

        def update_data():
            global keys, ciphertexts, file_sizes, e_values, plaintext_sizes, findings, last_updated
            while True:
                try:
                    if os.path.exists(JSON_FILE):
                        with open(JSON_FILE, "r") as f:
                            data = json.load(f)
                        keys = np.array(data.get("keys", []))
                        ciphertexts = np.array(data.get("ciphertexts", []))
                        file_sizes = np.array(data.get("file_sizes", []))
                        e_values = np.array(data.get("e_values", []))
                        plaintext_sizes = np.array(data.get("plaintext_sizes", []))
                        findings = data.get("findings", {})

                        last_updated = time.strftime("%Y-%m-%d %H:%M:%S")
                        print("Data updated from JSON at:", last_updated)
                    else:
                        print(f"JSON file not found: {JSON_FILE}")

                except Exception as e:
                    print(f"Error updating data from JSON: {e}")
                time.sleep(update_interval)

        update_thread = Thread(target=update_data)
        update_thread.daemon = True  # Daemons scary
        update_thread.start()

        return app

    def connect_to_remote(app, host='0.0.0.0', port=5000):
        """
        Runs the Flask app, making it accessible from other computers on the network.

        Args:
            app: The Flask app instance.
            host: The hostname to listen on. '0.0.0.0' makes the app accessible
                  from any address.
            port: The port to listen on.
        """
        print(f"Running the app on port {port}, other computers can connect to this via the local network")
        app.run(host=host, port=port, debug=True)
    
    app = create_flask_app(keys, ciphertexts, file_sizes, e_values, plaintext_sizes, findings)
    connect_to_remote(app, host='0.0.0.0', port=5000)


if __name__ == "__main__" and terminate != True:

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
    parser.add_argument('--run-flask', action='store_true', help='Run the Flask visualization server.')
    args = parser.parse_args()

    log("=== RSA Pattern Analysis Started ===")
    try:
        while True:
            findings = run_all_checks(args)

            try:
                with open(JSONFILE, "w") as jf:
                    json.dump(findings, jf)
            except Exception as e:
                log(f"Error writing to JSON file: {e}")

            log("Batch complete.\n")
            if args.run_flask:
                log("Starting Flask server...\n")
                keys, ciphertexts, file_sizes, e_values, plaintext_sizes = generate_sample_data() 
                run_flask(args, keys, ciphertexts, file_sizes, e_values, plaintext_sizes, findings) 
                log("Flask server stopped.\n")

            time.sleep(3)

    except KeyboardInterrupt:
        log("=== RSA Pattern Analysis Stopped ===")
