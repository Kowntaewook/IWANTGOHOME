// Fixed metadata projection for a fresh, bounded headless project.
// No process execution, networking, decompiler scripts, or target-controlled plugins.
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import com.google.gson.Gson;

public class FinderMetadata extends HeadlessScript {
    public void run() throws Exception {
        if (getScriptArgs().length != 1) throw new IllegalArgumentException("Expected fixed output path");
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("language_id", currentProgram.getLanguageID().toString());
        result.put("format", currentProgram.getExecutableFormat());
        result.put("image_base", currentProgram.getImageBase().toString());
        result.put("analysis_timed_out", analysisTimeoutOccurred());
        ArrayList<Object> functions = new ArrayList<>();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            if (functions.size() >= 2000) throw new IllegalStateException("Function metadata limit");
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", function.getName());
            row.put("entry", function.getEntryPoint().toString());
            row.put("external", function.isExternal());
            functions.add(row);
        }
        ArrayList<Object> symbols = new ArrayList<>();
        for (Symbol symbol : currentProgram.getSymbolTable().getAllSymbols(true)) {
            monitor.checkCancelled();
            if (symbols.size() >= 4000) throw new IllegalStateException("Symbol metadata limit");
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", symbol.getName());
            row.put("address", symbol.getAddress().toString());
            row.put("type", symbol.getSymbolType().toString());
            symbols.add(row);
        }
        result.put("functions", functions);
        result.put("symbols", symbols);
        Files.writeString(Path.of(getScriptArgs()[0]), new Gson().toJson(result), StandardOpenOption.CREATE_NEW);
    }
}
