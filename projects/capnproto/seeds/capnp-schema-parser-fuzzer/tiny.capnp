@0x123456789abcdef0;
struct Foo {
  bar @0 :Text;
  baz @1 :Int32 = 42;
  list @2 :List(UInt8);
  union {
    a @3 :Bool;
    b @4 :Float64;
  }
}
enum Color { red @0; green @1; blue @2; }
interface Iface {
  method @0 (x :Foo) -> (y :Color);
}
