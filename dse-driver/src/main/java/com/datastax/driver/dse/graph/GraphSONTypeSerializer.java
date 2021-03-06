/*
 *      Copyright (C) 2012-2016 DataStax Inc.
 *
 *      This software can be used solely with DataStax Enterprise. Please consult the license at
 *      http://www.datastax.com/terms/datastax-dse-driver-license-terms
 */
package com.datastax.driver.dse.graph;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.BeanProperty;
import com.fasterxml.jackson.databind.jsontype.TypeIdResolver;
import com.fasterxml.jackson.databind.jsontype.TypeSerializer;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;

/**
 * Extension of the Jackson's default TypeSerializer. An instance of this object will be passed to the serializers
 * on which they can safely call the utility methods to serialize types and making it compatible with the version
 * 2.0 of GraphSON.
 */
class GraphSONTypeSerializer extends TypeSerializer {

    private final TypeIdResolver idRes;
    private final String propertyName;
    private final TypeInfo typeInfo;
    private final String valuePropertyName;

    GraphSONTypeSerializer(final TypeIdResolver idRes, final String propertyName, final TypeInfo typeInfo,
                           final String valuePropertyName) {
        this.idRes = idRes;
        this.propertyName = propertyName;
        this.typeInfo = typeInfo;
        this.valuePropertyName = valuePropertyName;
    }

    @Override
    public TypeSerializer forProperty(final BeanProperty beanProperty) {
        return this;
    }

    @Override
    public JsonTypeInfo.As getTypeInclusion() {
        return null;
    }

    @Override
    public String getPropertyName() {
        return propertyName;
    }

    @Override
    public TypeIdResolver getTypeIdResolver() {
        return idRes;
    }

    @Override
    public void writeTypePrefixForScalar(final Object o, final JsonGenerator jsonGenerator) throws IOException {
        if (canWriteTypeId()) {
            writeTypePrefix(jsonGenerator, getTypeIdResolver().idFromValueAndType(o, getClassFromObject(o)));
        }
    }

    @Override
    public void writeTypePrefixForObject(final Object o, final JsonGenerator jsonGenerator) throws IOException {
        jsonGenerator.writeStartObject();
        // TODO: FULL_TYPES should be implemented here as : if (fullTypesModeEnabled()) writeTypePrefix(Map);
    }

    @Override
    public void writeTypePrefixForArray(final Object o, final JsonGenerator jsonGenerator) throws IOException {
        jsonGenerator.writeStartArray();
        // TODO: FULL_TYPES should be implemented here as : if (fullTypesModeEnabled()) writeTypePrefix(List);
    }

    @Override
    public void writeTypeSuffixForScalar(final Object o, final JsonGenerator jsonGenerator) throws IOException {
        if (canWriteTypeId()) {
            writeTypeSuffix(jsonGenerator);
        }
    }

    @Override
    public void writeTypeSuffixForObject(final Object o, final JsonGenerator jsonGenerator) throws IOException {
        jsonGenerator.writeEndObject();
        // TODO: FULL_TYPES should be implemented here as : if (fullTypesModeEnabled()) writeTypeSuffix(Map);
    }

    @Override
    public void writeTypeSuffixForArray(final Object o, final JsonGenerator jsonGenerator) throws IOException {
        jsonGenerator.writeEndArray();
        // TODO: FULL_TYPES should be implemented here as : if (fullTypesModeEnabled()) writeTypeSuffix(List);
    }

    @Override
    public void writeCustomTypePrefixForScalar(final Object o, final JsonGenerator jsonGenerator, final String s) throws IOException {
        if (canWriteTypeId()) {
            writeTypePrefix(jsonGenerator, s);
        }
    }

    @Override
    public void writeCustomTypePrefixForObject(final Object o, final JsonGenerator jsonGenerator, final String s) throws IOException {
        jsonGenerator.writeStartObject();
        // TODO: FULL_TYPES should be implemented here as : if (fullTypesModeEnabled()) writeTypePrefix(s);
    }

    @Override
    public void writeCustomTypePrefixForArray(final Object o, final JsonGenerator jsonGenerator, final String s) throws IOException {
        jsonGenerator.writeStartArray();
        // TODO: FULL_TYPES should be implemented here as : if (fullTypesModeEnabled()) writeTypePrefix(s);
    }

    @Override
    public void writeCustomTypeSuffixForScalar(final Object o, final JsonGenerator jsonGenerator, final String s) throws IOException {
        if (canWriteTypeId()) {
            writeTypeSuffix(jsonGenerator);
        }
    }

    @Override
    public void writeCustomTypeSuffixForObject(final Object o, final JsonGenerator jsonGenerator, final String s) throws IOException {
        jsonGenerator.writeEndObject();
        // TODO: FULL_TYPES should be implemented here as : if (fullTypesModeEnabled()) writeTypeSuffix(s);
    }

    @Override
    public void writeCustomTypeSuffixForArray(final Object o, final JsonGenerator jsonGenerator,final String s) throws IOException {
        jsonGenerator.writeEndArray();
        // TODO: FULL_TYPES should be implemented here as : if (fullTypesModeEnabled()) writeTypeSuffix(s);
    }

    private boolean canWriteTypeId() {
        return typeInfo != null
                && typeInfo == TypeInfo.PARTIAL_TYPES;
    }

    private void writeTypePrefix(final JsonGenerator jsonGenerator, final String s) throws IOException {
        jsonGenerator.writeStartObject();
        jsonGenerator.writeStringField(this.getPropertyName(), s);
        jsonGenerator.writeFieldName(this.valuePropertyName);
    }

    private void writeTypeSuffix(final JsonGenerator jsonGenerator) throws IOException {
        jsonGenerator.writeEndObject();
    }

    /* We force only **one** translation of a Java object to a domain specific object.
     i.e. users register typeIDs and serializers/deserializers for the predefined
     types we have in the spec. Graph, Vertex, Edge, VertexProperty, etc... And
     **not** their implementations (TinkerGraph, DetachedVertex, TinkerEdge,
     etc..)
    */
    private Class getClassFromObject(final Object o) {
        // not the most efficient
        final Class c = o.getClass();
        if (Vertex.class.isAssignableFrom(c)) {
            return Vertex.class;
        } else if (Edge.class.isAssignableFrom(c)) {
            return Edge.class;
        } else if (VertexProperty.class.isAssignableFrom(c)) {
            return VertexProperty.class;
        } else if (Property.class.isAssignableFrom(c)) {
            return Property.class;
        } else if (Path.class.isAssignableFrom(c)) {
            return Path.class;
        } else if (InetAddress.class.isAssignableFrom(c)) {
            return InetAddress.class;
        } else if (ByteBuffer.class.isAssignableFrom(c)) {
            return ByteBuffer.class;
        }
        return c;
    }
}
