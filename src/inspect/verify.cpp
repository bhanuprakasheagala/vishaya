#include "inspect/verify.h"

#include "bundle/reader.h"
#include "bundle/sign.h"
#include "common/log.h"
#include "inspect/render.h"

#include <iostream>
#include <string>

namespace vishaya::inspect {

int run_verify(const std::string& bundle_path, const std::string& pinned_key_b64) {
  try {
    vishaya::bundle::Reader reader(bundle_path);
    const auto& m      = reader.manifest();
    const auto  report = reader.verify();  // logs per-file/signature warnings to stderr

    // schema/tool are manifest strings from an attacker-controlled bundle → scrub.
    std::cout << "bundle:     " << bundle_path << "\n";
    std::cout << "schema:     " << scrub_for_terminal(m.schema_version)
              << "   tool: " << scrub_for_terminal(m.tool_name)
              << " " << scrub_for_terminal(m.tool_version) << "\n";
    std::cout << "integrity:  " << (report.integrity_ok ? "OK" : "MISMATCH") << "\n";

    // Pinned-key check: satisfied by default; only enforced when a pin was given.
    bool pinned_ok = pinned_key_b64.empty();

    if (!report.signature_present) {
      std::cout << "signature:  (unsigned)\n";
      if (!pinned_key_b64.empty()) {
        std::cout << "pinned key: NO SIGNATURE to check\n";
        pinned_ok = false;
      }
    } else {
      // sig.algorithm/scope are manifest strings from an attacker-controlled
      // bundle (printed even when the signature is INVALID) → scrub.
      std::cout << "signature:  " << scrub_for_terminal(m.sig.algorithm)
                << " (scope=" << scrub_for_terminal(m.sig.scope.empty() ? "legacy" : m.sig.scope) << ")  "
                << (report.signature_ok ? "VALID" : "INVALID") << "\n";
      std::cout << "key:        fingerprint "
                << vishaya::bundle::pubkey_fingerprint(m.sig.pubkey_b64) << "\n";
      if (!pinned_key_b64.empty()) {
        const bool key_matches = (m.sig.pubkey_b64 == pinned_key_b64);
        // A pinned key only proves identity if the signature it names actually
        // verified — otherwise the key field is just an unverified claim.
        pinned_ok = key_matches && report.signature_ok;
        if (key_matches && !report.signature_ok)
          std::cout << "pinned key: matches, but SIGNATURE INVALID\n";
        else
          std::cout << "pinned key: " << (key_matches ? "MATCH" : "MISMATCH") << "\n";
      } else {
        // Honesty: without a pinned key we cannot assert identity — the signing
        // key travels in the bundle, so a valid signature is tamper-evidence
        // (the content matches the key that signed it), not attestation.
        std::cout << "note:       key is unpinned; signature proves integrity, "
                     "not identity (use --verify-key to assert who signed)\n";
      }
    }

    const bool verified = report.ok() && pinned_ok;
    std::string verdict;
    if (!verified) {
      verdict = "FAILED";
    } else if (!report.signature_present) {
      verdict = "OK (unsigned — integrity verified, no signature)";
    } else {
      verdict = "VERIFIED";
    }
    std::cout << "VERDICT:    " << verdict << "\n";
    return verified ? 0 : 1;
  } catch (const std::exception& e) {
    vishaya::log::error(std::string("verify failed: ") + e.what());
    return 1;
  }
}

} // namespace vishaya::inspect
