// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.time.Duration;
import java.util.Collections;
import java.io.ByteArrayInputStream;
import static org.hibernate.validator.internal.util.CollectionHelper.newHashSet;

import jakarta.validation.ClockProvider;

import org.hibernate.validator.constraintvalidation.HibernateConstraintValidatorInitializationContext;
import org.hibernate.validator.internal.engine.ConstraintCreationContext;
import org.hibernate.validator.internal.engine.DefaultClockProvider;
import org.hibernate.validator.internal.engine.constraintvalidation.ConstraintValidatorFactoryImpl;
import org.hibernate.validator.internal.engine.constraintvalidation.ConstraintValidatorManagerImpl;
import org.hibernate.validator.internal.engine.scripting.DefaultScriptEvaluatorFactory;
import org.hibernate.validator.internal.engine.valueextraction.ValueExtractorManager;
import org.hibernate.validator.internal.metadata.core.ConstraintHelper;
import org.hibernate.validator.internal.util.TypeResolutionHelper;
import org.hibernate.validator.spi.scripting.ScriptEvaluator;
import org.hibernate.validator.spi.scripting.ScriptEvaluatorFactory;
import java.io.InputStream;
import java.util.Set;

import jakarta.validation.ValidationException;

import org.hibernate.validator.internal.engine.DefaultPropertyNodeNameProvider;
import org.hibernate.validator.internal.properties.DefaultGetterPropertySelectionStrategy;
import org.hibernate.validator.internal.properties.javabean.JavaBeanHelper;
import org.hibernate.validator.internal.xml.mapping.MappingXmlParser;


public class MappingParserFuzzer {
    public static ConstraintCreationContext getDummyConstraintCreationContext() {
		return new ConstraintCreationContext( ConstraintHelper.forAllBuiltinConstraints(),
				new ConstraintValidatorManagerImpl( 
                    new ConstraintValidatorFactoryImpl(), 
                    getConstraintValidatorInitializationContext( 
                        new DefaultScriptEvaluatorFactory( null ), 
                        DefaultClockProvider.INSTANCE, 
                        Duration.ZERO 
                        ) 
                    ),
				new TypeResolutionHelper(),
				new ValueExtractorManager( Collections.emptySet() ) 
                );
	}

	public static HibernateConstraintValidatorInitializationContext getConstraintValidatorInitializationContext(
			ScriptEvaluatorFactory scriptEvaluatorFactory, ClockProvider clockProvider, Duration duration
	) {
		return new HibernateConstraintValidatorInitializationContext() {

			@Override
			public ScriptEvaluator getScriptEvaluatorForLanguage(String languageName) {
				return scriptEvaluatorFactory.getScriptEvaluatorByLanguageName( languageName );
			}

			@Override
			public ClockProvider getClockProvider() {
				return clockProvider;
			}

			@Override
			public Duration getTemporalValidationTolerance() {
				return duration;
			}
		};
	}
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        ConstraintCreationContext constraintCreationContext = getDummyConstraintCreationContext();
        MappingXmlParser xmlMappingParser = new MappingXmlParser(
                constraintCreationContext,
                new JavaBeanHelper( new DefaultGetterPropertySelectionStrategy(), new DefaultPropertyNodeNameProvider() ), null
        );

        Set<InputStream> mappingStreams = newHashSet();
        for(int i = 0; i < data.consumeInt(1,10); i++)
		    mappingStreams.add( new ByteArrayInputStream(data.consumeBytes(4096))) ;


		try {
			xmlMappingParser.parse( mappingStreams );
		}
		catch (ValidationException e) {
		}
    }
}