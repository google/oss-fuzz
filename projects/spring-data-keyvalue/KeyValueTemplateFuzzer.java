// Copyright 2022 Google LLC
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
import lombok.Data;
import lombok.AllArgsConstructor;
import org.springframework.data.keyvalue.core.KeyValueTemplate;
import org.springframework.data.keyvalue.annotation.KeySpace;
import org.springframework.data.keyvalue.core.query.KeyValueQuery;
import org.springframework.data.map.MapKeyValueAdapter;
import org.springframework.data.annotation.Id;
import org.springframework.core.annotation.AliasFor;
import org.springframework.data.annotation.Persistent;
import java.io.Serializable;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.List;
import org.springframework.dao.DuplicateKeyException;

import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.expression.spel.SpelParseException;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.data.mapping.MappingException;
import org.springframework.data.keyvalue.core.UncategorizedKeyValueException;


public class KeyValueTemplateFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    String foo_id = data.consumeString(1000);
    String bar_id = data.consumeString(1000);
    String aliased_id = data.consumeString(1000);
    String subclass_id = data.consumeString(1000);
    String foo_input = data.consumeString(1000);    
    Foo foo = new Foo(foo_input);
    Bar bar = new Bar(data.consumeString(1000));
    ClassWithTypeAlias aliased = new ClassWithTypeAlias(data.consumeString(1000));
    SubclassOfAliasedType subclass_of_aliased = new SubclassOfAliasedType(data.consumeString(1000));
	  KeyValueQuery<String> STRING_QUERY = new KeyValueQuery<>("foo == '" + foo_input + "'");

    
    KeyValueTemplate operations = new KeyValueTemplate(new MapKeyValueAdapter());   
   
     try{
      operations.insert(foo_id, foo);
      operations.insert(bar_id, bar);
      operations.insert(aliased_id, aliased);
      operations.insert(subclass_id, subclass_of_aliased);
    }
    catch (DuplicateKeyException e){}

    operations.update(foo_id, bar);
    
    operations.findById(foo_id, Foo.class);
    operations.findById(bar_id, Bar.class);
    operations.findById(foo_id, Bar.class);
    operations.findById(aliased_id, ClassWithTypeAlias.class);
    try {
      operations.find(new KeyValueQuery<>(data.consumeString(1000)), Foo.class);
    }
    //catching the Spel* exceptions because they are not the focus and essentially block the fuzzer
    catch (DataRetrievalFailureException | SpelParseException | SpelEvaluationException | UncategorizedKeyValueException e){}


    try {
      operations.find(new KeyValueQuery<>(STRING_QUERY), Foo.class);
      operations.find(new KeyValueQuery<>(STRING_QUERY), ClassWithTypeAlias.class);
      operations.find(new KeyValueQuery<>(STRING_QUERY), SubclassOfAliasedType.class);
    }
    catch (DataRetrievalFailureException | UncategorizedKeyValueException e){}
  
    
    operations.findAll(foo.getClass());
    operations.findAll(aliased.getClass());
    operations.findAll(subclass_of_aliased.getClass());
    
    operations.delete(data.consumeString(1000), Foo.class);
    operations.delete(foo_id, Foo.class);

  }
  

	@Data
	@AllArgsConstructor
	static class Foo {

		String foo;

	}

	@Data
	@AllArgsConstructor
	static class Bar {

		String bar;
	}

	@Data
	static class ClassWithStringId implements Serializable {

		private static final long serialVersionUID = -7481030649267602830L;
		@Id String id;
		String value;
	}

	@ExplicitKeySpace(name = "aliased")
	@Data
	static class ClassWithTypeAlias implements Serializable {

		private static final long serialVersionUID = -5921943364908784571L;
		@Id String id;
		String name;

		ClassWithTypeAlias(String name) {
			this.name = name;
		}
	}

	static class SubclassOfAliasedType extends ClassWithTypeAlias {

		private static final long serialVersionUID = -468809596668871479L;

		SubclassOfAliasedType(String name) {
			super(name);
		}

	}

	@KeySpace
	@Persistent
	@Retention(RetentionPolicy.RUNTIME)
	@Target({ ElementType.TYPE })
	@interface ExplicitKeySpace {

		@AliasFor(annotation = KeySpace.class, value = "value")
		String name() default "";

	}
}




