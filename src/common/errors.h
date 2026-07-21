#pragma once

/*
 * File Notes:
 * - Exception hierarchy for Vishaya. All subclasses inherit from vishaya::Error,
 *   which inherits from std::runtime_error. Callers may catch by category
 *   (IsolationError, BundleError, CaptureError) or by base class.
 */

#include <stdexcept>

namespace vishaya {

class Error : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class IsolationError : public Error {
 public:
  using Error::Error;
};

class BundleError : public Error {
 public:
  using Error::Error;
};

class CaptureError : public Error {
 public:
  using Error::Error;
};

} // namespace vishaya
