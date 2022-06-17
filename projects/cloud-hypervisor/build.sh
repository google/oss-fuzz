cd $SRC/cloud-hypervisor
cargo fuzz build -O
cp cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/block $OUT/
cp cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/qcow $OUT/
cp cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/vhdx $OUT/