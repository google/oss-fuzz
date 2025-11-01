+++
authors = ["OSS-Fuzz Maintainers"]
title = "Introducing Java fuzz harness synthesis using LLMs"
date = "2024-09-05"
description = "Introducing LLM-based harness generation for Java OSS-Fuzz projects."
categories = [
    "Fuzzing",
    "Fuzzing synthesis",
    "LLM",
    "Automated fuzzing",
    "Java",
    "Java automatic fuzzing",
]
+++


# Introduction

The primary objective of OSS-Fuzz-gen is to automate the fuzzing process for open-source software.
In our previous blog posts ([1](https://security.googleblog.com/2023/08/ai-powered-fuzzing-breaking-bug-hunting.html),[2](https://blog.oss-fuzz.com/posts/introducing-llm-based-harness-synthesis-for-unfuzzed-projects/)), we've demonstrated promising results using large language models (LLMs) to enhance existing C/C++ OSS-Fuzz projects and explored the potential of leveraging LLMs for initial OSS-Fuzz integrations.


In this blog post, we explore how we can extend this work to another language (Java), and the unique challenges we encountered while building Java-specific capabilities into our existing OSS-Fuzz-Gen workflow:

1. Extracting program analysis data from Java projects.
2. Generate LLM prompts based on program analysis targeted Java projects.

# Java fuzz harness sample and outline

To illustrate the typical structure of a Java fuzz harness, consider the following
example targeting the [Jettison](https://github.com/google/oss-fuzz/tree/master/projects/jettison) project, specifically the constructor of the
`MappedXMLStreamReader` class. This constructor requires a `JSONObject` as an argument,
which the harness instantiates using fuzz data provided by the `FuzzedDataProvider`
object. Moreover, since `MappedXMLStreamReader` is a resource class implementing the
`AutoCloseable` interface, the harness must invoke the close method on the instantiated
object to prevent memory exhaustion. Failure to do so would result in memory
leaks during each fuzz iteration. 


The harness also needs to handle `JSONException` and `XMLStreamException` exceptions,
as these are valid exceptions that the target class may throw. If these exceptions
are not appropriately caught, they would be incorrectly reported as issues, leading
to false positives. It is also important to note that the methods targeted by the
harness are publicly accessible, as otherwise the harness wouldn’t build successfully.

```java
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.codehaus.jettison.mapped.MappedXMLStreamReader;
import org.codehaus.jettison.json.JSONObject;
import org.codehaus.jettison.json.JSONException;
import javax.xml.stream.XMLStreamException;

public class JsonFuzzer {
  public static void fuzzerInitialize() {
  }

  public static void fuzzerTearDown() {
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      JSONObject jsonObject = new JSONObject();
      for (int i = 0; i < 10; ++i) {
        try {
          jsonObject.put(data.consumeString(10), data.consumeString(10));
        } catch (JSONException e) {
          // handle exception
        }
      }
      MappedXMLStreamReader reader = new MappedXMLStreamReader(jsonObject);
      reader.close();
    } catch (JSONException | XMLStreamException e) {
      // handle exception
    }
  }
}
```


These aspects are central in the generation of Java fuzzing harnesses, and, we
may see similar code structures in a C++ harness, one of the observations that we
have made during our Java fuzzing automation efforts is that without contextual
information regarding the aforementioned parts the LLMs are likely to generate
harnesses that can’t build or produce false positives. To this end, a significant
part of enabling Java fuzzing harness synthesis by way of LLMs has been to provide
enough context to the LLM so it is aware of these constraints.

# Challenges faced integrating Java into OSS-Fuzz-gen

The above example highlights several common characteristics of Java harnesses,
and throughout our efforts we identified the need for specific handling of these
within our prompt. This includes specific considerations to the following attributes:

## 1. Object creation and constructors

Fuzzing Java targets almost always requires creating and managing objects, and this involves calling constructors, managing object lifecycles, and ensuring objects are in valid states before invoking methods. Because precise object management is crucial, it is important to provide context about object creation to LLMs so they can generate fuzzing harnesses that use the correct constructors or static methods. 

For example, our auto-generation capabilities support generating harnesses targeting both static methods and object instance methods. Whenever the target is an instance method we provide details about the constructors associated with a given class, and further descriptions about the types of the arguments to the construct. This constructor section that we add to the LLM prompt, provides details such as a list of constructors, methods and guidelines in the target code that create and initialize objects of the type that the target method is attached to.

A sample of this section is shown below, where the goal of the constructor section is to provide context for the LLM on how to instantiate a `DiffRowGenerator` object.

```sh
<constructor>
<signature>DiffRowGenerator.Builder.build()</signature>
<prerequisite>
You MUST call the STATIC method DiffRowGenerator.create() to retrieve an instance of DiffRowGenerator.Builder before invoking DiffRowGenerator.Builder.build() to generate a com.github.difflib.text.DiffRowGenerator instance.
</prerequisite>
</constructor>
```

For the full prompt and the harness generated by the prompt, please see the following [Gist](https://gist.github.com/DavidKorczynski/d16bf21a433931d6c8be9f5a4048f48e).

## 2. Exception handling

Exceptions are prevalent in Java and although they are also prevalent in C++, we found a need for adding further handling of exceptions when auto generating Java harnesses. We anticipate that this is, to some extent, due to Java fuzzing often revolving around generating harnesses that are meant to flag any uncaught exceptions in the target code, whereas the predominant goal of C++ fuzzing is to capture memory corruption issues. To this end, we added a specific guide on which exceptions a Java harness needs to catch as displayed in the prompt snippet below:

```sh
The <exceptions> tag contains a list of exceptions thrown by the target method that you MUST catch.
...
<exceptions>
<exception>jakarta.mail.internet.AddressException</exception>
</exceptions>
```

In order to extract the exceptions that a harness should catch, we rely on reachability analysis from Fuzz Introspector, that extracts the exceptions a given function can throw explicitly. The primary objective of including this section is to minimize the number of false positives arising from expected exceptions and to catch all checked exceptions, thereby preventing compilation errors in the generated harness.

## 3. Resources object closing

In Java fuzzing we must manage and close resources for classes that implement `AutoCloseable`
to prevent memory leaks and resource exhaustion. Java relies on the garbage collector
for memory management so a harness generally doesn’t need to worry about out-of-memory
issues or memory leaks. However, for classes that implement the `AutoCloseable` interface,
such as file streams, network connections, or database handles, the garbage collector won’t
free up its allocated memory. To this end, in order to avoid memory leaks and out-of-memory
issues, we need to provide context for the LLM whenever `AutoCloseable` objects are and guidance
for closing the objects correctly. To address this, we add to the LLM prompt general guidance
on the need for closing `AutoCloseable` interfaces, as well as specific guidance whenever
we incur objects that implements this interface, as shown by the snippet of a prompt below:

```sh
...
<item>You MUST invoke the close method of the org.codehaus.jettison.mapped.MappedXMLStreamReader objects in the finally block after the target method is invoked.</item>
<item>You MUST invoke the close method of any resource class objects that implements the java.lang.AutoCloseable interface in the finally block after the target method is invoked.</item>
...
```

## 4. Choosing suitable targets
A central theme when auto-generating fuzzing harnesses is to identify entry points in the target code that are relevant fuzz targets. In general, OSS-Fuzz-gen does this by identifying target functions that exhibit a lot of complexity, but has zero or low code coverage from the existing OSS-Fuzz harnesses. This works well in terms of identifying targets that if fuzzed correctly will yield a lot of code coverage. This idea translates well into Java as well, in that we are interested in fuzzing targets that are high in the function call tree of the target codebase.

However, we found that we need additional filtering mechanisms when choosing target method candidates, due to the language features of Java such as polymorphism, method scope and more. In addition to this, because Java targets often have several thousand methods that are potential candidates, we found a stronger need for more carefully choosing which candidates may be viable targets. For example, in addition to the existing candidate choosing mechanisms we have in OSS-Fuzz-gen, we added filtering logic for Java methods that only includes methods if they:
- Are publicly accessible.
- Are not part of the JVM library.
- Are not part of an enum class.
- Are not called by any existing fuzzing harnesses
- Are not part of any exception or testing class or contain the words “test”, “exception” or “error in the function name.


## 5. Random objects and primitive data

Java harnesses often have to generate complex types as input to the target methods, and these types themselves are often generated either through creation of a sequence of different objects or using helper methods provided by helper classes exposed by the Jazzer fuzzing framework. We found the need to provide further guidance on how to instantiate the arguments of a given function, as well provide guidance on generating simple types such as strings seeded with fuzz data. To this end, we include in each prompt a section on how to instantiate the arguments of a target method, as shown by the below snippet:

```sh
<arguments>
1. Argument #0 requires a java.util.List instance with a generic type of String. You MUST create an empty java.util.List<String> instance, then fill the list with multiple DIFFERENT String objects generated by FuzzedDataProvider::consumeString(int) or FuzzedDataProvider::consumeAsciiString(int) or FuzzedDataProvider::consumeRemainingAsString() or FuzzedDataProvider::consumeRemainingAsAsciiString() or FuzzedDataProvider::pickValue(String[]) methods.
2. Argument #1 requires a com.github.difflib.patch.Patch instance with a generic type of String. You MUST create two empty java.util.List<String> instance, then fill the two lists with multiple DIFFERENT String objects generated by FuzzedDataProvider::consumeString(int) or FuzzedDataProvider::consumeAsciiString(int) or FuzzedDataProvider::consumeRemainingAsString() or FuzzedDataProvider::consumeRemainingAsAsciiString() or FuzzedDataProvider::pickValue(String[]) methods. After the two lists creation, use these newly created lists to invoke the STATIC method com.github.difflib.DiffUtils.diff(java.util.List<String>,java.util.List<String>) to generate a com.github.difflib.patch.Patch instance with generic type of String.
</arguments>
```

The section outlines both how to create primitive types using the `FuzzedDataProvider` exposed by the fuzzing engine, as well as guidelines on how to create higher-level types such as the `difflib.patch.Patch` as shown in the second argument in the above snippet.

## 6. General Java fuzzing requirements

There are several fuzzing engines for Java, such as JQF, Jazzer, and JavaFuzz, each with its own unique structure and methodology, unlike the more standardized engines used for C/C++ fuzzing. Currently, OSS-Fuzz supports Java fuzzing exclusively through the Jazzer engine, so it is essential for OSS-Fuzz-Gen to provide guidelines that enable LLMs to generate harnesses following Jazzer's specific structure for direct use in OSS-Fuzz. We found a need to guide the LLM towards generating Jazzer-friendly harnesses by providing a Java-specific introduction section in the LLM, as well as a section on general Java fuzzing guidelines. 

An example snippet of the general guidelines are shown in the snippet below:

```sh
<requirements>
...
<item>The generated fuzzing harness should be wrapped with the <java_code> tag.</item>
<item>NEVER use any methods from the <code>java.lang.Random</code> class in the generated code.</item>
<item>NEVER use any classes or methods in the <code>java.lang.reflect</code> package in the generated code.</item>
<item>NEVER use the @FuzzTest annotation for specifying the fuzzing method.</item>
<item>Please avoid using any multithreading or multi-processing approach.</item>
<item>Please add import statements for necessary classes, except for classes in the java.lang package.</item>
<item>You MUST create the object before calling the target method.</item>
<item>You MUST catch java.lang.RuntimeException.</item>
<item>Please use HeaderTokenizerFuzzer as the Java class name.</item>
```


# Results

The Java harness generation logic is built into OSS-Fuzz-gen which means we can run the logic at scale. To test our approach we ran the harness generation on a total of 106 existing Java project integrations in OSS-Fuzz. An overview of the results are shown in the below table. In total we tried to synthesize harnesses for 592 targets, which means that we identified 592 interesting Java methods to fuzz. In total, 280 of the harnesses synthesized were able to build and of these 280 harnesses a total of  102 harnesses had an edge-coverage delta of more than zero. This means that 102 harnesses had code exploration, where the remaining 178 harnesses either ran into an exception in the first iteration or failed to explore code incrementally.

| Total number of projects | Total harnesses synthesized | Harnesses successfully built | harness build success rate | Harnesses with edge coverage delta above 0 |
|--------------------------|----------------------------|--------------------|-----------------|----------------|
| 106 | 592 | 280 | 47.30% | 102 |

During our evaluation, several of the harnesses reported bugs which we triaged. We found that two issues were deemed to be security issues (awaiting response) and also triaged four issues that were considered reliability bugs. All issues were reported to the upstream maintainers. In the following we’ll go through the four harnesses that found reliability bugs (uncaught exceptions). 

## Reliability bug 1: uncaught exception in jakarta.mail

Reported [here](https://github.com/jakartaee/mail-api/issues/734)

Generated harness:

```java
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import jakarta.mail.internet.ParameterList;
import jakarta.mail.internet.ParseException;

public class HeaderTokenizerFuzzer {
  public static void fuzzerInitialize() {
  }

  public static void fuzzerTearDown() {
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      for (int i = 0; i < 10; i++) {
        String var_0 = data.consumeRemainingAsString();
        ParameterList parameterList = new ParameterList(var_0);
      }
    } catch (ParseException e) {
    }
  }
}
```

Execution log and bug trace:

```sh
#2  INITED cov: 34 ft: 34 corp: 1/1b exec/s: 0 rss: 911Mb
#6  NEW    cov: 51 ft: 69 corp: 2/3b lim: 4 exec/s: 0 rss: 911Mb L: 2/2 MS: 8 ChangeByte-Custom-ChangeBit-Custom-CopyPart-Custom-InsertByte-Custom-
#12 NEW    cov: 60 ft: 79 corp: 3/5b lim: 4 exec/s: 0 rss: 911Mb L: 2/2 MS: 2 InsertByte-Custom-
#14 NEW    cov: 62 ft: 82 corp: 4/8b lim: 4 exec/s: 0 rss: 911Mb L: 3/3 MS: 4 ShuffleBytes-Custom-InsertByte-Custom-
#15 NEW    cov: 63 ft: 83 corp: 5/10b lim: 4 exec/s: 0 rss: 911Mb L: 2/3 MS: 2 ChangeByte-Custom-
#16 REDUCE cov: 63 ft: 83 corp: 5/9b lim: 4 exec/s: 0 rss: 911Mb L: 2/2 MS: 2 EraseBytes-Custom-
#25 NEW    cov: 64 ft: 84 corp: 6/11b lim: 4 exec/s: 0 rss: 911Mb L: 2/2 MS: 8 ShuffleBytes-Custom-ChangeByte-Custom-ChangeByte-Custom-CopyPart-Custom-
#54 NEW    cov: 71 ft: 91 corp: 7/14b lim: 4 exec/s: 0 rss: 911Mb L: 3/3 MS: 8 ChangeBinInt-Custom-CrossOver-Custom-InsertByte-Custom-ChangeBit-Custom-
#60 NEW    cov: 73 ft: 95 corp: 8/16b lim: 4 exec/s: 0 rss: 911Mb L: 2/3 MS: 2 CopyPart-Custom-

…
#232899 REDUCE cov: 247 ft: 1033 corp: 288/8318b lim: 493 exec/s: 116449 rss: 936Mb L: 14/260 MS: 2 EraseBytes-Custom-
#234061 REDUCE cov: 247 ft: 1033 corp: 288/8317b lim: 501 exec/s: 117030 rss: 936Mb L: 13/260 MS: 4 ChangeBit-Custom-EraseBytes-Custom-
#234662 REDUCE cov: 247 ft: 1033 corp: 288/8309b lim: 501 exec/s: 117331 rss: 936Mb L: 33/260 MS: 2 EraseBytes-Custom-
#236110 REDUCE cov: 247 ft: 1033 corp: 288/8305b lim: 509 exec/s: 118055 rss: 936Mb L: 25/260 MS: 6 ShuffleBytes-Custom-CMP-Custom-EraseBytes-Custom- DE: "*0*"-
#236377 REDUCE cov: 247 ft: 1033 corp: 288/8304b lim: 509 exec/s: 118188 rss: 936Mb L: 42/260 MS: 4 ChangeBit-Custom-EraseBytes-Custom-
#236528 REDUCE cov: 247 ft: 1033 corp: 288/8303b lim: 509 exec/s: 118264 rss: 936Mb L: 8/260 MS: 2 EraseBytes-Custom-
#238094 NEW    cov: 247 ft: 1037 corp: 289/8336b lim: 517 exec/s: 119047 rss: 936Mb L: 33/260 MS: 2 CopyPart-Custom-

== Java Exception: java.util.ConcurrentModificationException
    at java.base/java.util.HashMap$HashIterator.nextNode(HashMap.java:1584)
    at java.base/java.util.HashMap$KeyIterator.next(HashMap.java:1607)
    at jakarta.mail.internet.ParameterList.combineMultisegmentNames(ParameterList.java:408)
    at jakarta.mail.internet.ParameterList.<init>(ParameterList.java:309)
    at HeaderTokenizerFuzzer.fuzzerTestOneInput(HeaderTokenizerFuzzer.java:16)
```


## Reliability bug 2: uncaught exception in jettison.json

Reported [here](https://github.com/jettison-json/jettison/issues/96)

Generated harness:

```java
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONTokener;

public class JsonFuzzer {
  public static void fuzzerInitialize() {
  }

  public static void fuzzerTearDown() {
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      
      JSONTokener jSONTokener = new JSONTokener(data.consumeRemainingAsString());
      JSONArray jSONArray = new JSONArray(jSONTokener);
    } catch (JSONException e) {
    }
  }
}
```

Execution log and bug trace:

```sh
#1729   INITED cov: 88 ft: 341 corp: 67/2733b exec/s: 0 rss: 954Mb
#1731   NEW    cov: 90 ft: 343 corp: 68/2742b lim: 567 exec/s: 0 rss: 954Mb L: 9/558 MS: 4 CopyPart-Custom-ManualDict-Custom- DE: "}="-
#1758   NEW    cov: 92 ft: 345 corp: 69/2747b lim: 567 exec/s: 0 rss: 954Mb L: 5/558 MS: 4 PersAutoDict-Custom-CrossOver-Custom- DE: "}="-
#1759   REDUCE cov: 92 ft: 345 corp: 69/2745b lim: 567 exec/s: 0 rss: 954Mb L: 9/558 MS: 2 EraseBytes-Custom-
#1763   NEW    cov: 94 ft: 347 corp: 70/2820b lim: 567 exec/s: 0 rss: 954Mb L: 75/558 MS: 8 ChangeASCIIInt-Custom-EraseBytes-Custom-ShuffleBytes-Custom-CopyPart-Custom-
#1779   NEW    cov: 96 ft: 349 corp: 71/2853b lim: 567 exec/s: 0 rss: 954Mb L: 33/558 MS: 2 ManualDict-Custom- DE: "\""-
#1804   NEW    cov: 98 ft: 351 corp: 72/2864b lim: 567 exec/s: 0 rss: 954Mb L: 11/558 MS: 10 CMP-Custom-ChangeBit-Custom-ChangeBinInt-Custom-InsertByte-Custom-ChangeByte-Custom- DE: "<E"-
#1815   NEW    cov: 101 ft: 356 corp: 73/2871b lim: 567 exec/s: 0 rss: 954Mb L: 7/558 MS: 2 InsertByte-Custom-
…
#3620   NEW    cov: 142 ft: 440 corp: 122/6357b lim: 567 exec/s: 0 rss: 932Mb L: 7/558 MS: 2 InsertByte-Custom-
#3718   NEW    cov: 143 ft: 443 corp: 123/6509b lim: 567 exec/s: 0 rss: 932Mb L: 152/558 MS: 6 ChangeBit-Custom-ChangeByte-Custom-ManualDict-Custom- DE: "{\"foo\":nul"-
#3774   REDUCE cov: 143 ft: 443 corp: 123/6458b lim: 567 exec/s: 0 rss: 932Mb L: 61/558 MS: 2 CrossOver-Custom-
#3851   NEW    cov: 143 ft: 444 corp: 124/6487b lim: 567 exec/s: 0 rss: 932Mb L: 29/558 MS: 4 ChangeBinInt-Custom-PersAutoDict-Custom- DE: "//"-

== Java Exception: java.lang.NumberFormatException: For input string: "D[  " under radix 16
    at java.base/java.lang.NumberFormatException.forInputString(NumberFormatException.java:68)
    at java.base/java.lang.Integer.parseInt(Integer.java:652)
    at org.codehaus.jettison.json.JSONTokener.nextString(JSONTokener.java:258)
    at org.codehaus.jettison.json.JSONTokener.nextValue(JSONTokener.java:336)
    at org.codehaus.jettison.json.JSONArray.<init>(JSONArray.java:145)
    at org.codehaus.jettison.json.JSONTokener.newJSONArray(JSONTokener.java:436)
    at org.codehaus.jettison.json.JSONTokener.nextValue(JSONTokener.java:342)
    at org.codehaus.jettison.json.JSONArray.<init>(JSONArray.java:145)
    at org.codehaus.jettison.json.JSONTokener.newJSONArray(JSONTokener.java:436)
    at org.codehaus.jettison.json.JSONTokener.nextValue(JSONTokener.java:342)
    at org.codehaus.jettison.json.JSONArray.<init>(JSONArray.java:145)
    at org.codehaus.jettison.json.JSONTokener.newJSONArray(JSONTokener.java:436)
    at org.codehaus.jettison.json.JSONTokener.nextValue(JSONTokener.java:342)
    at org.codehaus.jettison.json.JSONArray.<init>(JSONArray.java:145)
    at org.codehaus.jettison.json.JSONTokener.newJSONArray(JSONTokener.java:436)
    at org.codehaus.jettison.json.JSONTokener.nextValue(JSONTokener.java:342)
    at org.codehaus.jettison.json.JSONArray.<init>(JSONArray.java:145)
    at org.codehaus.jettison.json.JSONTokener.newJSONArray(JSONTokener.java:436)
    at org.codehaus.jettison.json.JSONTokener.nextValue(JSONTokener.java:342)
    at org.codehaus.jettison.json.JSONArray.<init>(JSONArray.java:145)
    at org.codehaus.jettison.json.JSONTokener.newJSONArray(JSONTokener.java:436)
    at org.codehaus.jettison.json.JSONTokener.nextValue(JSONTokener.java:342)
    at org.codehaus.jettison.json.JSONArray.<init>(JSONArray.java:145)
    at org.codehaus.jettison.json.JSONTokener.newJSONArray(JSONTokener.java:436)
    at org.codehaus.jettison.json.JSONTokener.nextValue(JSONTokener.java:342)
    at org.codehaus.jettison.json.JSONArray.<init>(JSONArray.java:145)
    at org.codehaus.jettison.json.JSONTokener.newJSONArray(JSONTokener.java:436)
    at org.codehaus.jettison.json.JSONTokener.nextValue(JSONTokener.java:342)
    at org.codehaus.jettison.json.JSONArray.<init>(JSONArray.java:145)
    at org.codehaus.jettison.json.JSONTokener.newJSONArray(JSONTokener.java:436)
    at org.codehaus.jettison.json.JSONTokener.nextValue(JSONTokener.java:342)
    at org.codehaus.jettison.json.JSONArray.<init>(JSONArray.java:145)
    at org.codehaus.jettison.json.JSONTokener.newJSONArray(JSONTokener.java:436)
    at org.codehaus.jettison.json.JSONTokener.nextValue(JSONTokener.java:342)
    at org.codehaus.jettison.json.JSONArray.<init>(JSONArray.java:145)
    at JsonFuzzer.fuzzerTestOneInput(JsonFuzzer.java:17)
```

## Reliability bug 3: Uncaught exception in sqlite-jdbc

Reported [here](https://github.com/xerial/sqlite-jdbc/issues/1141)

Generated harness:

```java
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.sqlite.ExtendedCommand;

public class SqliteConnectionFuzzer {
  public static void fuzzerInitialize() {
    // Initializing objects for fuzzing
  }

  public static void fuzzerTearDown() {
    // Tear down objects after fuzzing
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    // Use the FuzzedDataProvider object to generate random data for fuzzing
    String string0 = data.consumeRemainingAsString();
    for (int i = 0; i < 100; i++) {
      for (int j = 0; j < 100; j++) {
        // Fuzz by invoking the target method with random parameters / objects generated above.
        ExtendedCommand.removeQuotation(string0);
      }
    }
  }
}
```

Execution log and bug trace:

```sh
#2  INITED cov: 9 ft: 9 corp: 1/1b exec/s: 0 rss: 942Mb
#486    NEW    cov: 10 ft: 10 corp: 2/3b lim: 8 exec/s: 486 rss: 1042Mb L: 2/2 MS: 8 ChangeByte-Custom-ChangeBit-Custom-CopyPart-Custom-ChangeBit-Custom-

== Java Exception: java.lang.StringIndexOutOfBoundsException: begin 1, end 0, length 1
    at java.base/java.lang.String.checkBoundsBeginEnd(String.java:3734)
    at java.base/java.lang.String.substring(String.java:1903)
    at org.sqlite.ExtendedCommand.removeQuotation(ExtendedCommand.java:57)
    at SqliteConnectionFuzzer.fuzzerTestOneInput(SqliteConnectionFuzzer.java:19)
```


## Reliability bug 4: uncaught exception in jolt

Reported [here](https://github.com/bazaarvoice/jolt/issues/1268)

Generated harness:
```java
import com.bazaarvoice.jolt.removr.spec.RemovrCompositeSpec;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.util.Map;
import java.util.HashMap;

public class JsonUtilsFuzzer {
  public static void fuzzerInitialize() {
  }

  public static void fuzzerTearDown() {
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
        String var_0 = data.consumeString(1024);
        Map<String, Object> var_1 = new HashMap<String, Object>();
        for (int i = 0; i < data.consumeInt(0, 10); i++) {
            var_1.put(data.consumeString(1024), data.consumeString(1024));
        }
        RemovrCompositeSpec target = new RemovrCompositeSpec(var_0, var_1);
    } catch (java.lang.UnsupportedOperationException e) {
    }
  }
}
```

Execution log and bug trace:

```sh
#358    NEW    cov: 52 ft: 67 corp: 12/35b lim: 4 exec/s: 0 rss: 990Mb L: 4/4 MS: 6 ChangeBinInt-Custom-PersAutoDict-Custom-CopyPart-Custom- DE: "\000\000"-
#411    NEW    cov: 54 ft: 70 corp: 13/39b lim: 4 exec/s: 0 rss: 990Mb L: 4/4 MS: 6 CrossOver-Custom-ShuffleBytes-Custom-CopyPart-Custom-
#468    REDUCE cov: 54 ft: 70 corp: 13/38b lim: 4 exec/s: 0 rss: 990Mb L: 2/4 MS: 4 ChangeBit-Custom-CrossOver-Custom-
#469    REDUCE cov: 54 ft: 70 corp: 13/37b lim: 4 exec/s: 0 rss: 990Mb L: 2/4 MS: 2 CrossOver-Custom-

== Java Exception: java.lang.ArrayIndexOutOfBoundsException: Index 1 out of bounds for length 1
    at com.bazaarvoice.jolt.common.pathelement.StarDoublePathElement.<init>(StarDoublePathElement.java:54)
    at com.bazaarvoice.jolt.removr.spec.RemovrSpec.parse(RemovrSpec.java:55)
    at com.bazaarvoice.jolt.removr.spec.RemovrSpec.<init>(RemovrSpec.java:36)
    at com.bazaarvoice.jolt.removr.spec.RemovrCompositeSpec.<init>(RemovrCompositeSpec.java:59)
    at JsonUtilsFuzzer.fuzzerTestOneInput(JsonUtilsFuzzer.java:20)
```

# Conclusions and future work

In this blog post we have introduced our initial efforts toward automated java fuzzing. We described the challenges we faced during integration of Java support to OSS-Fuzz-gen, including how we pick interesting candidates and how we provide Java-specific context in the LLM prompts. The approach is built into our existing pipelines in OSS-Fuzz-gen, which enables us to do harness generation at scale for all OSS-Fuzz Java projects. The approach has shown interesting elements including code coverage gains across a large part of the Java projects as well as reporting security and reliability issues.

We will continue our efforts in automated Java fuzzer generation and are actively exploring new avenues for prompt generation. The goal is to provide reliable and clear harness suggestions to OSS-Fuzz users. We are also exploring combining our Java efforts with approaches for generating OSS-Fuzz integrations from scratch, as described in a previous [blog post](https://blog.oss-fuzz.com/posts/introducing-llm-based-harness-synthesis-for-unfuzzed-projects/).

The efforts described in this blog post are available in our OSS-Fuzz-gen repository [https://github.com/google/oss-fuzz-gen](https://github.com/google/oss-fuzz-gen) and we invite contributions from the community to further the Java harness automation generation.
