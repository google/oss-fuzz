package com.sun.xml.rpc.processor.modeler.rmi;

import com.sun.xml.rpc.util.JAXRPCClassFactory;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;


public class SOAPSimpleTypeCreatorFuzzer {

    private FuzzedDataProvider fuzzedDataProvider;

    public SOAPSimpleTypeCreatorFuzzer(FuzzedDataProvider fuzzedDataProvider) throws Exception {
        this.fuzzedDataProvider = fuzzedDataProvider;
    }

    void test() {
        String data = fuzzedDataProvider.consumeRemainingAsString();

        JAXRPCClassFactory factory = JAXRPCClassFactory.newInstance();
        
        try {
            factory.createSOAPSimpleTypeCreator().getJavaSimpleType(data);
        } catch (Exception e) {
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider)  throws Exception {

        SOAPSimpleTypeCreatorFuzzer fixture = new SOAPSimpleTypeCreatorFuzzer(fuzzedDataProvider);
        fixture.test();
    }
}