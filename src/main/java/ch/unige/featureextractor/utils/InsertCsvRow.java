/*
 * Copyright (c)  Benedetto Marco Serinelli
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package ch.unige.featureextractor.utils;

import ch.unige.featureextractor.Main;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tika.io.IOUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class InsertCsvRow {
    private static final Logger logger = LogManager.getLogger(Main.class);
    private final String header;
    private final List<String> rows;
    private String savepath = null;
    private String filename = null;

    public InsertCsvRow(String header, List<String> rows, String savepath, String filename) {
        this.header = header;
        this.rows = rows;
        this.savepath = savepath;
        this.filename = filename;
    }

    public InsertCsvRow(String header, String row, String savepath, String filename) {

        this.header = header;
        this.rows = new ArrayList<>();
        this.savepath = savepath;
        this.filename = filename;

        rows.add(row);
    }

    public static void insert(String header, List<String> rows, String savepath, String filename) {
        if (savepath == null || filename == null || rows == null || rows.size() <= 0) {
            String ex = String.format("savepath=%s,filename=%s", savepath, filename);
            throw new IllegalArgumentException(ex);
        }

        File fileSavPath = new File(savepath);

        if (!fileSavPath.exists()) {
            fileSavPath.mkdirs();
        }

        if (!savepath.endsWith(ExtractorFeaturesModel.FILE_SEP)) {
            savepath += ExtractorFeaturesModel.FILE_SEP;
        }

        File file = new File(savepath + filename);
        FileOutputStream output = null;

        try {
            if (file.exists()) {
                output = new FileOutputStream(file, true);
            } else {
                if (file.createNewFile()) {
                    output = new FileOutputStream(file);
                }
                if (header != null) {
                    output.write((header + ExtractorFeaturesModel.LINE_SEP).getBytes());
                }
            }
            for (String row : rows) {
                output.write((row + ExtractorFeaturesModel.LINE_SEP).getBytes());
            }

        } catch (IOException e) {
            logger.debug(e.getMessage());
        } finally {
            try {
                if (output != null) {
                    output.flush();
                    IOUtils.closeQuietly(output);
                }
            } catch (IOException e) {
                logger.debug(e.getMessage());
            }
        }
    }
}
