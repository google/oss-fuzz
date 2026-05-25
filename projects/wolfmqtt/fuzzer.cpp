// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <fuzzing/datasource/datasource.hpp>
#include <wolfmqtt/mqtt_client.h>
#include <wolfmqtt/mqtt_packet.h>
#include <optional>

#define CHECK_EQ(expr, res) if ( (expr) != (res) ) { goto end; }
#define CHECK_NE(expr, res) if ( (expr) == (res) ) { goto end; }

#define BADPTR ((void*)0x12)
#define MAX_TOPICS 50

#define DEBUG 0

class Base {
    protected:
        fuzzing::datasource::Datasource& ds;
        MqttQoS GetQoS(void) const;
    public:
        Base(fuzzing::datasource::Datasource& ds);
        ~Base();
};

Base::Base(fuzzing::datasource::Datasource& ds) :
    ds(ds)
{ }

Base::~Base() { }

MqttQoS Base::GetQoS(void) const {
    switch ( ds.Get<uint8_t>() % 3 ) {
        case    0:
            return MQTT_QOS_0;
        case    1:
            return MQTT_QOS_1;
        case    2:
            return MQTT_QOS_2;
        default:
            /* Silence compiler warning */
            abort();
    }
}

class Topic : public Base {
    private:
        MqttTopic topic;
        std::vector<std::string> strings;
    public:
        Topic(fuzzing::datasource::Datasource& ds);
        ~Topic();
        bool Generate(void);
        MqttTopic Get(void);
};

Topic::Topic(fuzzing::datasource::Datasource& ds) :
    Base(ds)
{ }

Topic::~Topic() { }

bool Topic::Generate(void) {
    bool ret;

    memset(&topic, 0, sizeof(topic));

    strings.push_back( ds.Get<std::string>() );
    topic.topic_filter = strings.back().c_str();

    topic.qos = GetQoS();

    ret = true;
end:
    return ret;
}

MqttTopic Topic::Get(void) {
    return topic;
}

class Topics : public Base {
    private:
        std::vector<Topic*> topics;
    public:
        Topics(fuzzing::datasource::Datasource& ds);
        ~Topics();
        bool Generate(void);
        MqttTopic* ToArray(void);
        size_t Size(void) const;
};

Topics::Topics(fuzzing::datasource::Datasource& ds) :
    Base(ds)
{ }

Topics::~Topics() {
    for (auto& t : topics) {
        delete t;
    }
}
        
bool Topics::Generate(void) {
    bool ret;

    try {
        const auto numTopics = ds.Get<uint16_t>() % (MAX_TOPICS+1);

        for (size_t i = 0; i < numTopics; i++) {
            topics.push_back(new Topic(ds));
            CHECK_EQ(topics.back()->Generate(), true);
        }

        ret = true;
    } catch ( ... ) { }

end:
    return ret;
}

MqttTopic* Topics::ToArray(void) {
    auto ret = new MqttTopic[topics.size()];

    for (size_t i = 0; i < Size(); i++) {
        ret[i] = topics[i]->Get();
    }
    return ret;
}
        
size_t Topics::Size(void) const {
    return topics.size();
}

class wolfMQTTFuzzer : public Base {
        MqttClient client;
        MqttNet net;
        MqttConnect connect;

        uint8_t* tx_buf = nullptr, *rx_buf = nullptr;
        size_t tx_size = 0, rx_size = 0;

        std::string client_id;

        void* malloc(const size_t n);
        void free(void* ptr);

        word16 GetPacketId(void) const;
        std::optional<Topic> GetTopic(void) const;

        bool subscribe(void);
        bool unsubscribe(void);
        bool publish(void);
        bool ping(void);
        bool wait(void);
    public:
        wolfMQTTFuzzer(fuzzing::datasource::Datasource& ds);
        ~wolfMQTTFuzzer();
        bool Initialize(void);
        void Run(void);
        int recv(byte* buf, const int buf_len);
        int write(const int buf_len);

};

static int mqtt_connect(void *context, const char* host, word16 port, int timeout_ms)
{
    (void)context;
    (void)host;
    (void)port;
    (void)timeout_ms;

    return MQTT_CODE_SUCCESS;
}

static int mqtt_recv(void *context, byte* buf, int buf_len, int timeout_ms)
{
    (void)context;
    (void)timeout_ms;

    auto fuzzer = static_cast<wolfMQTTFuzzer*>(context);
    return fuzzer->recv(buf, buf_len);
}

static int mqtt_write(void *context, const byte* buf, int buf_len, int timeout_ms)
{
    (void)context;
    (void)timeout_ms;
    (void)buf;

    auto fuzzer = static_cast<wolfMQTTFuzzer*>(context);
    return fuzzer->write(buf_len);
}

static int mqtt_disconnect(void *context)
{
    (void)context;

    return MQTT_CODE_SUCCESS;
}

static int mqtt_message_cb(MqttClient *client, MqttMessage *msg, byte msg_new, byte msg_done)
{
    return MQTT_CODE_SUCCESS;
}

void* wolfMQTTFuzzer::malloc(const size_t n) {
    return n == 0 ? BADPTR : ::malloc(n);
}

void wolfMQTTFuzzer::free(void* ptr) {
    if ( ptr == BADPTR ) {
        return;
    }

    ::free(ptr);
}

std::optional<Topic> wolfMQTTFuzzer::GetTopic(void) const {
    Topic topic(ds);

    if ( topic.Generate() == false ) {
        return std::nullopt;
    }

    return topic;
}

word16 wolfMQTTFuzzer::GetPacketId(void) const {
    return ds.Get<word16>();
}

bool wolfMQTTFuzzer::subscribe(void) {
    MqttTopic* topicsArray = nullptr;

    bool ret = false;

    try {
        Topics topics(ds);
        CHECK_EQ(topics.Generate(), true);

        MqttSubscribe subscribe;

        memset(&subscribe, 0, sizeof(subscribe));

        subscribe.packet_id = GetPacketId();
        topicsArray = topics.ToArray();
        subscribe.topic_count = topics.Size();
        subscribe.topics = topicsArray;

        CHECK_EQ(MqttClient_Subscribe(&client, &subscribe), MQTT_CODE_SUCCESS);

        ret = true;
    } catch ( ... ) { }

end:
    if ( topicsArray ) {
        delete[] topicsArray;
    }
    return ret;
}

bool wolfMQTTFuzzer::unsubscribe(void) {
    MqttTopic* topicsArray = nullptr;

    bool ret = false;

    try {
        Topics topics(ds);
        CHECK_EQ(topics.Generate(), true);

        MqttUnsubscribe unsubscribe;

        memset(&unsubscribe, 0, sizeof(unsubscribe));

        unsubscribe.packet_id = GetPacketId();
        topicsArray = topics.ToArray();
        unsubscribe.topic_count = topics.Size();
        unsubscribe.topics = topicsArray;

        CHECK_EQ(MqttClient_Unsubscribe(&client, &unsubscribe), MQTT_CODE_SUCCESS);

        ret = true;
    } catch ( ... ) { }

end:
    if ( topicsArray ) {
        delete[] topicsArray;
    }
    return ret;
}

bool wolfMQTTFuzzer::publish(void) {
    bool ret = false;

    try {
        MqttPublish publish;

        memset(&publish, 0, sizeof(publish));

        publish.retain = ds.Get<bool>() ? 1 : 0;
        publish.qos = GetQoS();
        publish.duplicate = ds.Get<bool>() ? 1 : 0;

        const auto topic_str = ds.Get<std::string>();
        publish.topic_name = topic_str.c_str();

        publish.packet_id = GetPacketId();

        auto buffer = ds.GetData(0);
        publish.buffer = buffer.data();
        publish.total_len = buffer.size();

        if ( DEBUG ) {
            printf("publish: topic name size: %zu\n", strlen(topic_str.c_str()));
        }

        CHECK_EQ(MqttClient_Publish(&client, &publish), MQTT_CODE_SUCCESS);

        ret = true;
    } catch ( ... ) { }

end:
    return ret;
}

bool wolfMQTTFuzzer::ping(void) {
    bool ret = false;

    MqttPing ping;

    memset(&ping, 0, sizeof(ping));

    CHECK_EQ(MqttClient_Ping_ex(&client, &ping), true);

    ret = true;

end:
    return ret;
}

bool wolfMQTTFuzzer::wait(void) {
    bool ret = false;

    CHECK_EQ(MqttClient_WaitMessage(&client, 1000), MQTT_CODE_SUCCESS);

    ret = true;

end:
    return ret;
}

wolfMQTTFuzzer::wolfMQTTFuzzer(fuzzing::datasource::Datasource& ds) :
    Base(ds)
{ }

wolfMQTTFuzzer::~wolfMQTTFuzzer() {
    this->free(tx_buf);
    this->free(rx_buf);
}

bool wolfMQTTFuzzer::Initialize(void) {
    bool ret = false;

    try {
        /* net */
        {
            memset(&net, 0, sizeof(net));

            net.connect = mqtt_connect;
            net.read = mqtt_recv;
            net.write = mqtt_write;
            net.disconnect = mqtt_disconnect;
            net.context = this;
        }

        /* client */
        {
            memset(&client, 0, sizeof(client));

            tx_size = ds.Get<uint16_t>();
            tx_size = 4096;
            tx_buf = (uint8_t*)this->malloc(tx_size);
            rx_size = ds.Get<uint16_t>();
            rx_size = 4096;
            rx_buf = (uint8_t*)this->malloc(rx_size);
            memset(tx_buf, 0, tx_size);
            memset(rx_buf, 0, rx_size);

            client.msg_cb = mqtt_message_cb;
            client.tx_buf = tx_buf;
            client.tx_buf_len = tx_size;
            client.rx_buf = rx_buf;
            client.rx_buf_len = rx_size;
            client.cmd_timeout_ms = 1000;
        }

        /* connect */
        MqttMessage lwt_msg;
        {
            memset(&connect, 0, sizeof(connect));

            connect.keep_alive_sec = 1;
            connect.clean_session = ds.Get<bool>() ? 1 : 0;
            client_id = ds.Get<std::string>();
            connect.client_id = client_id.c_str();
            connect.enable_lwt = ds.Get<bool>() ? 1 : 0;
        }
            
        std::string lwt_topic_name;
        std::vector<uint8_t> lwt_buffer;

        if ( connect.enable_lwt ) {
            lwt_topic_name = ds.Get<std::string>();
            lwt_buffer = ds.GetData(0);

            connect.lwt_msg = &lwt_msg;
            lwt_msg.qos = GetQoS();
            lwt_msg.retain = ds.Get<bool>() ? 1 : 0;
            lwt_msg.topic_name = lwt_topic_name.c_str();
            lwt_msg.buffer = lwt_buffer.data();
            lwt_msg.total_len = lwt_buffer.size();
        }

        CHECK_EQ(MqttSocket_Init(&client, &net), MQTT_CODE_SUCCESS);

#if 0
        if ( ds.Get<bool>() ) {
            //CHECK_EQ(MqttClient_SetPropertyCallback(&client, mqtt_property_cb, NULL);
        }
#endif

        CHECK_EQ(MqttClient_NetConnect(&client, "dummy", 12345, 1000, 0, NULL), MQTT_CODE_SUCCESS);
        CHECK_EQ(MqttClient_Connect(&client, &connect), MQTT_CODE_SUCCESS);

        ret = true;

    } catch ( ... ) {
        return false;
    }

end:
    return ret;
}

void wolfMQTTFuzzer::Run(void) {
    try {
        const auto numActions = ds.Get<uint8_t>() % 20;

        for (size_t i = 0; i < numActions; i++) {
            switch ( ds.Get<uint8_t>() ) {
                case    0:
                    subscribe();
                    break;
                case    1:
                    unsubscribe();
                    break;
                case    2:
                    publish();
                    break;
                case    3:
                    ping();
                    break;
                case    4:
                    wait();
                    break;
            }
        }

        MqttClient_NetDisconnect(&client);
    } catch ( ... ) { }
}

int wolfMQTTFuzzer::recv(byte* buf, const int buf_len) {
    try {
        const auto data = ds.GetData(0);
        const size_t copySize = buf_len > data.size() ? data.size() : buf_len;
        if ( copySize ) {
            memcpy(buf, data.data(), copySize);
        }
        if ( DEBUG )
        {
            printf("Recv: %zu bytes (%d requested)\n", copySize, buf_len);
            for (size_t i = 0; i < copySize; i++) {
                printf("%02X ", data[i]);
            }
            printf("\n");
        }
        return copySize;
    } catch ( ... ) {
        if ( DEBUG ) printf("Recv: -1\n");
        return -1;
    }
}

int wolfMQTTFuzzer::write(const int buf_len) {
    try {
        if ( ds.Get<bool>() == true ) {
            if ( DEBUG ) printf("write: -1\n");
            return -1;
        }

        const auto ret = (int)(ds.Get<uint32_t>() % (buf_len+1));
        if ( DEBUG ) printf("write: %d bytes (%d requested)\n", ret, buf_len);
        return ret;
    } catch ( ... ) {
        return -1;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzzing::datasource::Datasource ds(data, size);
    wolfMQTTFuzzer fuzzer(ds);

    CHECK_EQ(fuzzer.Initialize(), true);

    fuzzer.Run();

end:
    return 0;
}
