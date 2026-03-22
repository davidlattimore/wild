template <typename T>
T get_value(T v) {
  // This static variable inside a template is what causes GCC to emit a symbol
  // as UNIQUE.
  static T def = 0;
  def++;
  return v + def;
}
