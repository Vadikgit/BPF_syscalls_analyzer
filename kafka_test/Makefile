KAFKA_CPPFLAGS=-Wall $(shell pkg-config --cflags glib-2.0 rdkafka)
KAFKA_LDLIBS=$(shell pkg-config --libs glib-2.0 rdkafka)


producer: producer.cpp
	$(call msg,BINARY,$@)
	@$(CXX) $(CXXFLAGS) $(INCLUDES) $(KAFKA_CPPFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz $(KAFKA_LDLIBS) -o $@
