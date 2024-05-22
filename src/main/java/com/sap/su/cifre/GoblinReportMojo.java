package com.sap.su.cifre;

// DOCUMENTATION
// - https://maven.apache.org/guides/plugin/guide-java-report-plugin-development.html

import java.util.Locale;
import java.util.Set;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.net.URL;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.util.Optional;

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

@Mojo(name = "goblin", defaultPhase = LifecyclePhase.SITE, requiresDependencyResolution = ResolutionScope.RUNTIME, requiresProject = true, threadSafe = true)
public class GoblinReportMojo extends AbstractMavenReport {
    @Parameter(property = "apiUrl", defaultValue = "http://localhost:8080")
    private String apiUrl;

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
        final List<String> FIELDS = List.of("CVE", "FRESHNESS");
        final List<String> COLUMNS = List.of("Artifact", "Version", "Scope", "CVE", "FRESHNESS");

        Set<Artifact> artifacts = project.getDependencyArtifacts();
        Map<Artifact, Map<String, String>> artifactMap = retrieveInformation(FIELDS, artifacts);

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
                mainSink.text(artifactMap.get(artifact).get(field));
                mainSink.tableCell_();
            }
            mainSink.tableRow_();
        }

        mainSink.table_();

        mainSink.section1_();
        mainSink.body_();
    }

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

    private Map<Artifact, Map<String, String>> retrieveInformation(List<String> fields, Set<Artifact> artifacts) {
        Map<Artifact, Map<String, String>> artifactMap = new HashMap<>();
        final String url = apiUrl + "/release";
        for (Artifact artifact : artifacts) {
            String artifactId = artifactId(artifact);
            Map<String, String> artifactInformation = new HashMap<>(fields.size());
            for (String field : fields) {
                artifactInformation.put(field, "xxx");
            }
            artifactMap.put(artifact, artifactInformation);
        }
        return artifactMap;
    }

}
