#/bin/bash

mkdir tmp
mkdir fonts
unzip PDFExtractTextFuzzer_seed_corpus.zip -d pdfs

#use mutool to extract the fonts and images
#keep the fonts. get rid of the images
#If there's a more efficient way to extract just the fonts, we should implement that

for file in pdfs/*.pdf; do
    echo "$(basename $file)"
    cp "$file" tmp
    cd tmp
    mutool extract "$(basename $file)"
    FONTS=($(find . -name "font-*" -printf '%P\n' 2>/dev/null))
    for fnt in "${FONTS[@]}"; do
        if [ ! -d "../fonts/${fnt##*.}" ]; then
            mkdir "../fonts/${fnt##*.}"
        fi
        cp "$fnt" "../fonts/${fnt##*.}/$(basename $file)-$fnt"
    done
    cd ..
    rm -rf tmp/*
done

if [ -d "fonts/cff" ]; then
    cd fonts/cff
    zip CFFParserFuzzer_seed_corpus.zip *.cff
    mv CFFParserFuzzer_seed_corpus.zip ../..
    cd ../..
fi

if [ -d "fonts/otf" ]; then
    cd fonts/cff
    zip OTFParserFuzzer_seed_corpus.zip *.otf
    mv OTFParserFuzzer_seed_corpus.zip ../.. 
    cd ../.. 
fi

if [ -d "fonts/ttf" ]; then
    cd fonts/ttf
    zip TTFParserFuzzer_seed_corpus.zip *.ttf
    mv TTFParserFuzzer_seed_corpus.zip ../.. 
    cd ../.. 
fi

if [ -d "fonts/otf" ]; then
    cd fonts/otf
    zip OTFParserFuzzer_seed_corpus.zip *.otf
    mv OTFParserFuzzer_seed_corpus.zip ../.. 
    cd ../.. 
fi

if [ -d "fonts/cid" ]; then
    cd fonts/cid
    zip Type1ParserFuzzer_seed_corpus.zip *.cid
    mv Type1ParserFuzzer_seed_corpus.zip ../.. 
    cd ../.. 
fi

if [ -d "fonts/pfa" ]; then
    cd fonts/pfa
    if [ -f "../../Type1ParserFuzzer_seed_corpus.zip"]; then
        mv ../../Type1ParserFuzzer_seed_corpus.zip .
        zip -u Type1ParserFuzzer_seed_corpus.zip *.pfa
    else
        zip Type1ParserFuzzer_seed_corpus.zip *.pfa
    fi
    mv Type1ParserFuzzer_seed_corpus.zip ../.. 
    cd ../.. 
fi

rm -rf fonts pdfs tmp
