import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import com.google.inject.*;
import com.google.inject.internal.Annotations;
import com.google.inject.internal.InternalFlags;
import com.google.inject.matcher.Matchers;
import com.google.inject.name.Named;
import com.google.inject.CreationException;
import com.google.inject.name.Names;
import static java.lang.annotation.RetentionPolicy.RUNTIME;
import static com.google.inject.name.Names.named;
import com.google.inject.ConfigurationException;

import java.lang.annotation.Retention;
import java.util.*;

public class InjectorFuzzer {

    @Retention(RUNTIME)
    @BindingAnnotation
    @interface NumericValue {}
    
    @Retention(RUNTIME)
    @BindingAnnotation
    @interface EnumValue {}
    
    @Retention(RUNTIME)
    @BindingAnnotation
    @interface ClassName {}

    public enum Bar {
        TEE,
        BAZ,
        BOB
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String value =  data.consumeRemainingAsString();

        try {
            Injector injector =
            Guice.createInjector(
                new AbstractModule() {
                    @Override
                    protected void configure() {
                        bindConstant().annotatedWith(NumericValue.class).to(value);
                        bindConstant().annotatedWith(EnumValue.class).to(value);
                        bindConstant().annotatedWith(ClassName.class).to(value);
                    }
                });

            DummyClass foo = injector.getInstance(DummyClass.class);

        } catch (CreationException | ConfigurationException e) { }
    }

    public static class DummyClass {
        @Inject @EnumValue Bar enumField;
        @Inject @ClassName Class<?> classField;
        @Inject @NumericValue Byte byteField;
    }
}