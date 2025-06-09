export const defaultPatterns = [
  // Personal data
  ['Phone number', '\\b\\d{3}[ -]?\\d{2}[ -]?\\d{2}[ -]?\\d{2}\\b'],
  ['Credit card number', '\\b(?:\\d[ -]*?){13,16}\\b'],
  ['Email address', '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b'],
  ['DNI/NIF (España)', '\\b\\d{8}[A-HJ-NP-TV-Z]\\b'],
  ['NIE (España)', '\\b[XYZ]\\d{7}[A-Z]\\b'],
  ['SSN (US)', '\\b\\d{3}-\\d{2}-\\d{4}\\b'],
  ['CURP (México)', '\\b[A-Z][AEIOU][A-Z]{2}\\d{6}[HM][A-Z]{2}[A-Z]{3}[A-Z0-9]\\d\\b'],
  ['RFC (México)', '\\b[A-ZÑ&]{3,4}\\d{6}[A-Z0-9]{3}\\b'],
  ['Passport', '\\b([A-Z]{1,2}\\d{7,8}|[A-Z0-9]{9})\\b'],

  // Bank accounts and cards
  ['IBAN', '\\b[A-Z]{2}\\d{2}[ ]?(?:\\d{4}[ ]?){3,7}\\d{1,4}\\b'],
  ['SWIFT/BIC', '\\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\\b'],
  ['Bank account (ES)', '\\b\\d{4} \\d{4} \\d{2} \\d{10}\\b'],

  // Addresses and locations
  ['IP address', '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b'],
  ['IPv6 address', '\\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\\b'],
  ['MAC address', '\\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\\b'],
];
