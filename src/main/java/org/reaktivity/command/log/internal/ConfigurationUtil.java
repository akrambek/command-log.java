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

import java.util.function.BiFunction;
import java.util.function.BooleanSupplier;
import java.util.function.IntSupplier;
import java.util.function.Supplier;

public class ConfigurationUtil
{
    private final BiFunction<String, String, String> getProperty;
    private final BiFunction<String, String, String> getPropertyDefault;

    public ConfigurationUtil()
    {
        this.getProperty = System::getProperty;
        this.getPropertyDefault = (p, d) -> d;
    }

    protected final int getInteger(String key, int defaultValue)
    {
        String value = getProperty(key, (String) null);
        if (value == null)
        {
            return defaultValue;
        }
        return Integer.decode(value);
    }

    protected final boolean getBoolean(String key, boolean defaultValue)
    {
        String value = getProperty(key, (String) null);
        if (value == null)
        {
            return defaultValue;
        }
        return Boolean.valueOf(value);
    }

    protected final String getProperty(String key, Supplier<String> defaultValue)
    {
        String value = getProperty(key, (String) null);
        if (value == null)
        {
            return defaultValue.get();
        }
        return value;
    }

    protected final int getInteger(String key, IntSupplier defaultValue)
    {
        String value = getProperty(key, (String) null);
        if (value == null)
        {
            return defaultValue.getAsInt();
        }
        return Integer.decode(value);
    }

    protected final boolean getBoolean(String key, BooleanSupplier defaultValue)
    {
        String value = getProperty(key, (String) null);
        if (value == null)
        {
            return defaultValue.getAsBoolean();
        }
        return Boolean.valueOf(value);
    }

    protected String getProperty(String key, String defaultValue)
    {
        return getProperty.apply(key, getPropertyDefault.apply(key, defaultValue));
    }
}
