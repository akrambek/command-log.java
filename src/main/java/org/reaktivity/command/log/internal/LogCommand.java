/**
 * Copyright 2016-2017 The Reaktivity Project
 *
 * The Reaktivity Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package org.reaktivity.command.log.internal;

import static org.apache.commons.cli.Option.builder;

import java.util.Properties;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.reaktivity.nukleus.Configuration;

public final class LogCommand
{
    public static void main(String[] args) throws Exception
    {
        CommandLineParser parser = new DefaultParser();

        Options options = new Options();
        options.addOption(builder("h").longOpt("help").desc("print this message").build());
        options.addOption(builder("t").hasArg()
                                      .required(false)
                                      .longOpt("type")
                                      .desc("streams* | streams-nowait | counters | queues | routes")
                                      .build());
        options.addOption(builder("d").longOpt("directory").hasArg().desc("configuration directory").build());
        options.addOption(builder("v").longOpt("verbose").desc("verbose output").build());

        CommandLine cmdline = parser.parse(options, args);

        if (cmdline.hasOption("help") || !cmdline.hasOption("directory"))
        {
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("log", options);
        }
        else
        {
            String directory = cmdline.getOptionValue("directory");
            boolean verbose = cmdline.hasOption("verbose");
            String type = cmdline.getOptionValue("type", "streams");

            Properties properties = new Properties();
            properties.setProperty(Configuration.DIRECTORY_PROPERTY_NAME, directory);

            final Configuration config = new LogCommandConfiguration(properties);

            if ("streams".equals(type) || "streams-nowait".equals(type))
            {
                new LogStreamsCommand(config, System.out::printf, verbose, "streams".equals(type)).invoke();
            }
            else if ("counters".equals(type))
            {
                new LogCountersCommand(config, System.out::printf, verbose).invoke();
            }
            else if ("queues".equals(type))
            {
                new LogQueueDepthCommand(config, System.out::printf, verbose).invoke();
            }
            else if ("routes".equals(type))
            {
                new LogRoutesCommand(config, System.out::printf, verbose).invoke();
            }
        }
    }
}
