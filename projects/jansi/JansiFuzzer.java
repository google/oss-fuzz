// Copyright 2023 Google LLC
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
///////////////////////////////////////////////////////////////////////////
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.util.EnumSet;
import org.fusesource.jansi.Ansi;
import org.fusesource.jansi.AnsiConsole;

public class JansiFuzzer {
  public static void fuzzerInitialize() {
    AnsiConsole.systemInstall();
  }

  public static void fuzzerTearDown() {
    AnsiConsole.systemUninstall();
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    Ansi ansi = Ansi.ansi();
    int[] choices = data.consumeInts(data.consumeInt(1, 10));

    for (Integer choice : choices) {
      switch (choice % 27) {
        case 0:
          ansi = ansi.fg(data.pickValue(EnumSet.allOf(Ansi.Color.class)));
          break;
        case 2:
          ansi = ansi.fg(data.consumeInt());
          break;
        case 3:
          ansi = ansi.fgRgb(data.consumeInt());
          break;
        case 4:
          ansi = ansi.fgRgb(data.consumeInt(), data.consumeInt(), data.consumeInt());
          break;
        case 5:
          ansi = ansi.fgBright(data.pickValue(EnumSet.allOf(Ansi.Color.class)));
          break;
        case 6:
          ansi = ansi.bg(data.pickValue(EnumSet.allOf(Ansi.Color.class)));
          break;
        case 7:
          ansi = ansi.bg(data.consumeInt());
          break;
        case 8:
          ansi = ansi.bgRgb(data.consumeInt());
          break;
        case 9:
          ansi = ansi.bgRgb(data.consumeInt(), data.consumeInt(), data.consumeInt());
          break;
        case 10:
          ansi = ansi.bgBright(data.pickValue(EnumSet.allOf(Ansi.Color.class)));
          break;
        case 11:
          ansi = ansi.a(data.pickValue(EnumSet.allOf(Ansi.Attribute.class)));
          break;
        case 12:
          ansi = ansi.cursor(data.consumeInt(), data.consumeInt());
          break;
        case 13:
          ansi = ansi.cursorToColumn(data.consumeInt());
          break;
        case 14:
          ansi = ansi.cursorUp(data.consumeInt());
          break;
        case 15:
          ansi = ansi.cursorDown(data.consumeInt());
          break;
        case 16:
          ansi = ansi.cursorRight(data.consumeInt());
          break;
        case 17:
          ansi = ansi.cursorLeft(data.consumeInt());
          break;
        case 18:
          ansi = ansi.cursorMove(data.consumeInt(), data.consumeInt());
          break;
        case 19:
          ansi = ansi.cursorUpLine(data.consumeInt());
          break;
        case 20:
          ansi = ansi.cursorDownLine(data.consumeInt());
          break;
        case 21:
          ansi = ansi.eraseScreen(data.pickValue(EnumSet.allOf(Ansi.Erase.class)));
          break;
        case 22:
          ansi = ansi.eraseLine(data.pickValue(EnumSet.allOf(Ansi.Erase.class)));
          break;
        case 23:
          ansi = ansi.scrollUp(data.consumeInt());
          break;
        case 24:
          ansi = ansi.scrollDown(data.consumeInt());
          break;
        case 25:
          ansi = ansi.a(data.consumeRemainingAsString());
          break;
        case 26:
          ansi = ansi.render(data.consumeRemainingAsString());
          break;
      }
    }
  }
}
