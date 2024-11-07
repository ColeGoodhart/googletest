#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <bitset>
#include <algorithm>
#include <limits>
#include <numeric>
#include <sstream>
#include <iterator>
#include <map>
#include <iomanip>
#include <cmath>

using namespace std;

int hamming_distance(const string& str1, const string& str2) {
    if (str1.size() != str2.size()) {
        cerr << "Strings must be of equal length." << endl;
        return -1;
    }

    int distance = 0;
    for (size_t i = 0; i < str1.size(); i++) {
        distance += bitset<8>(str1[i] ^ str2[i]).count();
    }
    return distance;
}

string base64_decode(const string& in) {
    const string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    string out;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (base64_chars.find(c) == string::npos) break;
        val = (val << 6) + base64_chars.find(c);
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

double average_normalized_distance(const string& ciphertext, size_t keysize) {
    size_t num_chunks = ciphertext.size() / keysize;
    if (num_chunks < 2) {
        return numeric_limits<double>::infinity();
    }

    double total_distance = 0.0;
    size_t comparisons = 0;

    for (size_t i = 0; i < num_chunks - 1; ++i) {
        string chunk1 = ciphertext.substr(i * keysize, keysize);
        string chunk2 = ciphertext.substr((i + 1) * keysize, keysize);
        total_distance += hamming_distance(chunk1, chunk2);
        comparisons++;
    }

    return (total_distance / comparisons) / keysize;
}

size_t find_best_key_size(const string& ciphertext, size_t min_size = 2, size_t max_size = 40) {
    vector<pair<size_t, double>> keysize_scores;

    for (size_t keysize = min_size; keysize <= max_size; ++keysize) {
        double score = average_normalized_distance(ciphertext, keysize);
        keysize_scores.push_back({keysize, score});
    }

    auto best_keysize = min_element(keysize_scores.begin(), keysize_scores.end(),
        [](const pair<size_t, double>& a, const pair<size_t, double>& b) {
            return a.second < b.second;
        });

    return best_keysize->first;
}

vector<string> break_into_blocks(const string& ciphertext, size_t keysize) {
    vector<string> blocks((ciphertext.size() + keysize - 1) / keysize);
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        blocks[i / keysize].push_back(ciphertext[i]);
    }
    return blocks;
}

vector<string> transpose_blocks(const vector<string>& blocks) {
    if (blocks.empty()) return {};
    size_t block_size = blocks[0].size();
    vector<string> transposed(block_size);
    for (const auto& block : blocks) {
        for (size_t i = 0; i < block.size(); ++i) {
            transposed[i] += block[i];
        }
    }
    return transposed;
}

pair<char, double> single_byte_xor(const string& block) {
    char best_key = 0;
    double best_score = numeric_limits<double>::max();

    for (int key = 0; key < 256; ++key) {
        string decrypted;
        for (char c : block) {
            decrypted += c ^ key;
        }

        double score = 0.0;
        for (char c : decrypted) {
            if (isprint(c) || isspace(c)) {
                score += 1.0;
            }
        }

        if (score < best_score) {
            best_score = score;
            best_key = key;
        }
    }
    return {best_key, best_score};
}

string find_repeating_key(const vector<string>& blocks) {
    string key;
    for (const auto& block : blocks) {
        key += single_byte_xor(block).first;
    }
    return key;
}

string decrypt(const string& ciphertext, const string& key) {
    string decrypted;
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        decrypted += ciphertext[i] ^ key[i % key.size()];
    }
    return decrypted;
}

int main() {
    string filename = "/Users/colegoodhart/Desktop/encrypted.txt";
    ifstream file(filename);
    if (!file) {
        cerr << "Failed to open the file: " << filename << endl;
        return 1;
    }

    stringstream buffer;
    buffer << file.rdbuf();
    string base64_ciphertext = buffer.str();

    string ciphertext = base64_decode(base64_ciphertext);

    size_t key_size = find_best_key_size(ciphertext);
    cout << "Most likely key size: " << key_size << endl;

    vector<string> blocks = break_into_blocks(ciphertext, key_size);
    vector<string> transposed = transpose_blocks(blocks);

    string key = find_repeating_key(transposed);
    cout << "Found key: " << key << endl;

    string decrypted_text = decrypt(ciphertext, key);
    cout << "Decrypted text:\n" << decrypted_text << endl;

    return 0;
}

