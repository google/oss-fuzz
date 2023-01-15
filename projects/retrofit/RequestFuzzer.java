// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in co  mpliance with the License.
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
//////////////////////////////////////////////////////////////////////////////////

package retrofit2;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.io.IOException;
import okhttp3.OkHttpClient;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okhttp3.MediaType;
import retrofit2.Retrofit;
import retrofit2.Call;
import retrofit2.converter.gson.GsonConverterFactory;
import retrofit2.http.Body;
import retrofit2.http.POST;

public class RequestFuzzer {
    interface CallMethod {
        @POST("/")
        Call<ResponseBody> postRequestBody(@Body RequestBody body);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String str = data.consumeString(500);
        String str1 = data.consumeString(500);
        String str2 = data.consumeString(500);
        String str3 = data.consumeString(500);
        String str4 = data.consumeString(500);
        String str5 = data.consumeString(500);
        String str6 = data.consumeRemainingAsString();

        OkHttpClient httpClient = new OkHttpClient.Builder()
                .addInterceptor(
                        new Interceptor() {
                            @Override
                            public Response intercept(Chain chain) throws IOException {
                                Request original = chain.request();
                                RequestBody body = RequestBody.create(MediaType.parse(str), str1);
                                Request request = original.newBuilder()
                                        .header(str2, str3)
                                        .header(str4, str5)
                                        .method(original.method(), body)
                                        .build();
                                return chain.proceed(request);
                            }
                        })
                .build();

        Retrofit retrofit = null;
        CallMethod service = null;

        try {
            retrofit = new Retrofit.Builder().baseUrl("http://localhost").addConverterFactory(GsonConverterFactory.create()).client(httpClient).build();
        } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
        }

        try {
            service = retrofit.create(CallMethod.class);
        } catch (NullPointerException e) {
        }

        try {
            service.postRequestBody(RequestBody.create(MediaType.parse(str), str6)).execute();
        } catch (IOException | RuntimeException e) {
        }
    }    
}