#!/bin/bash

echo "Starting build process of all source"

rs_levels=(opt0 opt1 opt2 opt3)

echo "------ Bat ------"
pushd bat
cp Cargo.toml bat/Cargo.toml
pushd bat
for l in ${rs_levels[@]};
do
	cargo build --profile $l
done
popd
popd

echo "------ Egg ------"
pushd egg
 for l in ${rs_levels[@]};
do
	cargo build --profile $l
done
popd

 
echo "------ Hyper ------"
pushd hyper
 for l in ${rs_levels[@]};
do
	cargo build --profile $l
done
popd
 
echo "------ Rust Coreutils ------"
pushd coreutils-rs
pushd coreutils
 for l in ${rs_levels[@]};
do
	cargo build --profile $l
done
popd
popd

echo "------ SQLite3 ------"
pushd sqlite
make all
popd
