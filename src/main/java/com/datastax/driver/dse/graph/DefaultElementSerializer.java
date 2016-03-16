/*
 *      Copyright (C) 2012-2016 DataStax Inc.
 */
package com.datastax.driver.dse.graph;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;

/**
 * Default element serializer used by the driver.
 * It serializes {@link Element} instances by writing their ids.
 */
class DefaultElementSerializer extends StdSerializer<Element> {

    DefaultElementSerializer() {
        super(Element.class);
    }

    @Override
    public void serialize(Element value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        gen.getCodec().writeValue(gen, value.getId());
    }

}
