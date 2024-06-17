package com.cifre.sap.su;

// DOCUMENTATION
// - https://maven.apache.org/guides/plugin/guide-java-report-plugin-development.html

import java.util.Locale;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Optional;

import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.MalformedURLException;
import java.net.URISyntaxException;

import org.apache.http.client.utils.URIBuilder;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.doxia.sink.Sink;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;
import org.apache.maven.reporting.AbstractMavenReport;
import org.apache.maven.reporting.MavenReportException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Mojo(name = "goblin", defaultPhase = LifecyclePhase.SITE, requiresDependencyResolution = ResolutionScope.RUNTIME, requiresProject = true, threadSafe = true)
public class GoblinReportMojo extends AbstractMavenReport {
    @Parameter(property = "apiUrl", defaultValue = "http://localhost:8080")
    private String apiUrl;

    private static final ObjectMapper objectMapper = new ObjectMapper();
    private final String releaseRoute = "/release";

    @Override
    public String getOutputName() {
        return "goblin-report";
    }

    @Override
    public String getName(Locale locale) {
        return "Goblin Report";
    }

    @Override
    public String getDescription(Locale locale) {
        return "A simple Goblin report";
    }

    @Override
    protected void executeReport(Locale locale) throws MavenReportException {
        MavenProject project = getProject();
        final List<String> FIELDS = List.of("cve_aggregated", "freshness");
        final List<String> COLUMNS = List.of("Artifact", "Version", "Scope", "Aggregated CVE",
                "Freshness (missed releases)");

        Set<Artifact> artifacts = project.getDependencyArtifacts();
        Map<Artifact, Optional<Map<String, Optional<String>>>> artifactMap = retrieveInformation(artifacts, FIELDS);

        Log logger = getLog();
        logger.info("Generating " + getOutputName() + ".html"
                + " for " + project.getName() + " " + project.getVersion());

        Sink mainSink = getSink();
        if (mainSink == null) {
            throw new MavenReportException("Could not get the Doxia sink");
        }

        mainSink.head();
        mainSink.title();
        mainSink.text("Simple Report for " + project.getName() + " " + project.getVersion());
        mainSink.title_();
        mainSink.head_();

        mainSink.body();

        mainSink.section1();
        mainSink.sectionTitle1();
        mainSink.text("Direct dependencies");
        mainSink.sectionTitle1_();

        mainSink.table();

        mainSink.tableRow();
        for (String column : COLUMNS) {
            mainSink.tableHeaderCell();
            mainSink.text(column);
            mainSink.tableHeaderCell_();
        }
        mainSink.tableRow_();

        for (Artifact artifact : artifacts) {
            mainSink.tableRow();
            mainSink.tableCell();
            String name = artifactId(artifact);
            Optional<URL> href = artifactUrl(artifact);
            if (href.isPresent()) {
                mainSink.link(href.get().toString());
                mainSink.text(name);
                mainSink.link_();
            } else {
                mainSink.text(name);
            }
            mainSink.tableCell_();

            mainSink.tableCell();
            mainSink.text(artifact.getVersion());
            mainSink.tableCell_();

            mainSink.tableCell();
            mainSink.text(artifact.getScope());
            mainSink.tableCell_();

            for (String field : FIELDS) {
                mainSink.tableCell();
                String value = artifactMap.get(artifact).flatMap(a -> a.get(field)).orElse("?");
                mainSink.text(value);
                mainSink.tableCell_();
            }
            mainSink.tableRow_();
        }

        mainSink.table_();

        mainSink.section1_();
        mainSink.body_();
    }

    /**
     * Returns the id of an artifact (i.e., a String of the form gid:aid).
     * 
     * @param artifact
     * @return the id of the artifact
     */
    private String artifactId(Artifact artifact) {
        return artifact.getGroupId() + ":" + artifact.getArtifactId();
    }

    private Optional<URL> artifactUrl(Artifact artifact) {
        try {
            URL url = new URIBuilder()
                    .setScheme("http")
                    .setHost("central.sonatype.com")
                    .setPath(String.format("/artifact/%s/%s", artifact.getGroupId(), artifact.getArtifactId()))
                    .build()
                    .toURL();
            return Optional.of(url);
        } catch (URISyntaxException | MalformedURLException e) {
            return Optional.empty();
        }
    }

    private Map<Artifact, Optional<Map<String, Optional<String>>>> retrieveInformation(Set<Artifact> artifacts,
            List<String> metrics) {
        Function<Artifact, Optional<Map<String, Optional<String>>>> mapper = a -> getMetricsForArtifact(a, metrics);
        return artifacts.stream().collect(Collectors.toMap(Function.identity(), mapper));
    }

    private Optional<Map<String, Optional<String>>> getMetricsForArtifact(Artifact artifact, List<String> metrics) {
        final String url = apiUrl + releaseRoute;

        Map<String, Object> requestData = new HashMap<>();
        requestData.put("groupId", artifact.getGroupId());
        requestData.put("artifactId", artifact.getArtifactId());
        requestData.put("version", artifact.getVersion());
        requestData.put("addedValues", metrics);

        Optional<Map<String, Optional<String>>> rtr;

        try {
            String requestBody = objectMapper.writeValueAsString(requestData);

            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200 && !response.body().equals("{}")) {
                rtr = Optional.of(extractValues(artifact, response.body(), metrics));
            } else {
                Log logger = getLog();
                logger.warn("Unknown release: " + artifact);
                rtr = Optional.empty();
            }
            client.close();
            return rtr;
        } catch (Exception e) {
            e.printStackTrace();
            return Optional.empty();
        }
    }

    private static final Map<String, Function<JsonNode, String>> extractors = new HashMap<>();
    static {
        extractors.put("cve_aggregated", String::valueOf);
        extractors.put("freshness", n -> n.get("numberMissedRelease").asText());
    }

    private Map<String, Optional<String>> extractValues(Artifact artifact, String responseBody, List<String> metrics)
            throws JsonProcessingException {
        JsonNode rootNode = objectMapper.readTree(responseBody);
        JsonNode nodes = rootNode.path("nodes").get(0);

        Map<String, Optional<String>> values = new HashMap<>();
        for (String metric : metrics) {
            JsonNode node = nodes.path(metric);
            if (!node.isMissingNode()) {
                values.put(metric, Optional.ofNullable(extractors.get(metric)).map(f -> f.apply(node)));
            } else {
                Log logger = getLog();
                logger.warn("Unknown metric " + metric + " for release " + artifact);
                values.put(metric, Optional.empty());
            }
        }
        return values;
    }

}
