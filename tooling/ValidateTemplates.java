import freemarker.template.Configuration;
import freemarker.template.Template;
import java.nio.file.Files;
import java.nio.file.Path;

/** Syntax validation only; real Keycloak rendering is verified separately. */
class ValidateTemplates {
    public static void main(String[] args) throws Exception {
        var configuration = new Configuration(Configuration.VERSION_2_3_34);
        try (var paths = Files.walk(Path.of(args[0]))) {
            for (var path : paths.filter(p -> p.toString().endsWith(".ftl")).sorted().toList()) {
                try (var reader = Files.newBufferedReader(path)) {
                    new Template(path.toString(), reader, configuration);
                }
                System.out.println("Parsed " + path);
            }
        }
    }
}
