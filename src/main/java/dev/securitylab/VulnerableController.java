package dev.securitylab;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Base64;

import javax.sql.DataSource;
import javax.xml.parsers.DocumentBuilderFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;
import org.w3c.dom.Document;

@RestController
public class VulnerableController {

    private static final Logger LOGGER = LoggerFactory.getLogger(VulnerableController.class);
    private static final String ADMIN_PASSWORD = "admin123";

    private final DataSource dataSource;

    public VulnerableController(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @GetMapping("/api/status")
    public String status() {
        return "vulnerability-lab-ready";
    }

    @GetMapping("/api/users")
    public String findUser(@RequestParam String name) throws Exception {
        String sql = "SELECT email FROM users WHERE name = '" + name + "'";
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet results = statement.executeQuery(sql)) {
            return results.next() ? results.getString("email") : "not found";
        }
    }

    @GetMapping("/api/run")
    public String runCommand(@RequestParam String command) throws Exception {
        Process process = new ProcessBuilder("sh", "-c", command).start();
        return new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }

    @GetMapping("/api/files")
    public String readFile(@RequestParam String name) throws Exception {
        return Files.readString(Path.of("samples").resolve(name));
    }

    @GetMapping(value = "/api/greeting", produces = MediaType.TEXT_HTML_VALUE)
    public String greeting(@RequestParam String name) {
        return "<html><body><h1>Hello " + name + "</h1></body></html>";
    }

    @GetMapping("/api/fetch")
    public String fetchUrl(@RequestParam String url) throws Exception {
        URL remoteUrl = URI.create(url).toURL();
        return new String(remoteUrl.openStream().readAllBytes(), StandardCharsets.UTF_8);
    }

    @GetMapping("/api/redirect")
    public RedirectView redirect(@RequestParam String url) {
        return new RedirectView(url);
    }

    @PostMapping(value = "/api/xml", consumes = MediaType.APPLICATION_XML_VALUE)
    public String parseXml(@RequestBody String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        Document document = factory.newDocumentBuilder().parse(
                new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        return document.getDocumentElement().getTextContent();
    }

    @PostMapping("/api/deserialize")
    public String deserialize(@RequestBody String encodedObject) throws Exception {
        byte[] serialized = Base64.getDecoder().decode(encodedObject);
        try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(serialized))) {
            return String.valueOf(input.readObject());
        }
    }

    @GetMapping("/api/hash")
    public String weakHash(@RequestParam String value) throws Exception {
        byte[] digest = MessageDigest.getInstance("MD5")
                .digest(value.getBytes(StandardCharsets.UTF_8));
        return java.util.HexFormat.of().formatHex(digest);
    }

    @PostMapping("/api/login")
    public ResponseEntity<String> login(@RequestParam String username, @RequestParam String password) {
        LOGGER.info("Login attempt for " + username);
        if ("admin".equals(username) && ADMIN_PASSWORD.equals(password)) {
            return ResponseEntity.ok("authenticated");
        }
        return ResponseEntity.status(401).body("denied");
    }
}