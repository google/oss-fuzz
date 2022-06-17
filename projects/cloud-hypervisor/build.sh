cd $SRC/cloud-hypervisor
cargo fuzz build -O
cp $SRC/cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/block $OUT/
cp $SRC/cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/qcow $OUT/
cp $SRC/cloud-hypervisor/fuzz/target/x86_64-unknown-linux-gnu/release/vhdx $OUT/