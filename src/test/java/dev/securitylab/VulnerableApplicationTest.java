package dev.securitylab;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class VulnerableApplicationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void applicationStarts() throws Exception {
        mockMvc.perform(get("/api/status"))
                .andExpect(status().isOk())
                .andExpect(content().string("vulnerability-lab-ready"));
    }

    @Test
    void databaseIsSeeded() throws Exception {
        mockMvc.perform(get("/api/users").param("name", "alice"))
                .andExpect(status().isOk())
                .andExpect(content().string("alice@example.test"));
    }

    @Test
    void weakHashEndpointIsDeterministic() throws Exception {
        mockMvc.perform(get("/api/hash").param("value", "test"))
                .andExpect(status().isOk())
                .andExpect(content().string("098f6bcd4621d373cade4e832627b4f6"));
    }
}