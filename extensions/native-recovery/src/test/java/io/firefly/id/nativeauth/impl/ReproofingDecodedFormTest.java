package io.firefly.id.nativeauth.impl;

import org.junit.jupiter.api.Test;
import jakarta.ws.rs.core.*;
import java.lang.reflect.*;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class ReproofingDecodedFormTest {
    private Method parser() {
        try { return ReproofingResourceImpl.class.getDeclaredMethod("form", MultivaluedMap.class, int.class); }
        catch (NoSuchMethodException missing) { fail("Missing bounded framework-decoded Keycloak form handling"); return null; }
    }
    @Test @SuppressWarnings("unchecked")
    void frameworkDecodedFormRemainsUsableAfterFrameworkConsumesTheInputStream() throws Exception {
        Method parser = parser(); var decoded = new MultivaluedHashMap<String,String>(); decoded.add("csrf","opaque-csrf"); decoded.add("username","customer");
        assertEquals(Map.of("csrf","opaque-csrf","username","customer"),(Map<String,String>)parser.invoke(null,decoded,128));
    }
    @Test void decodedParserStillRejectsDuplicateUnknownOversizedAndUnboundedForms() throws Exception {
        Method parser = parser(); var decoded = new MultivaluedHashMap<String,String>(); decoded.add("csrf","a");
        assertThrows(InvocationTargetException.class,()->parser.invoke(null,decoded,16385));
        assertThrows(InvocationTargetException.class,()->parser.invoke(null,decoded,-1));
        decoded.add("csrf","b"); assertThrows(InvocationTargetException.class,()->parser.invoke(null,decoded,128)); decoded.remove("csrf");
        decoded.add("approved","true"); assertThrows(InvocationTargetException.class,()->parser.invoke(null,decoded,128)); decoded.remove("approved");
        decoded.add("password","é".repeat(8193)); assertThrows(InvocationTargetException.class,()->parser.invoke(null,decoded,16384));
    }
}
