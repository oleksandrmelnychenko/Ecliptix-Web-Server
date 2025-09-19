#!/bin/bash

# Script to add author headers and remove inline comments from C# files
# Author: Oleksandr Melnychenko

AUTHOR_HEADER="/*
 * Ecliptix Security SSL Native Library
 * Author: Oleksandr Melnychenko
 */"

# Files to update with specific descriptions
declare -A file_descriptions
file_descriptions["Native/EcliptixServerNativeLibrary.cs"]="P/Invoke wrapper for the Ecliptix server security library"
file_descriptions["Native/EcliptixServerResult.cs"]="Result codes from the Ecliptix server security library"
file_descriptions["Native/EcliptixServerConstants.cs"]="Constants from the Ecliptix server security library"
file_descriptions["Resources/EmbeddedResourceLoader.cs"]="Helper class to load embedded resources containing private keys"
file_descriptions["Failures/ServerSecurityFailureType.cs"]="Server security failure types enumeration"
file_descriptions["Failures/ServerSecurityFailure.cs"]="Server security failure class with factory methods"
file_descriptions["Common/Result.cs"]="Result type for functional error handling"
file_descriptions["TestServerLibrary.cs"]="Test program for server security library"

cd Ecliptix.Security.SSL.Native

for file in "${!file_descriptions[@]}"; do
    if [ -f "$file" ]; then
        echo "Updating $file..."

        # Create header with specific description
        SPECIFIC_HEADER="/*
 * Ecliptix Security SSL Native Library
 * ${file_descriptions[$file]}
 * Author: Oleksandr Melnychenko
 */"

        # Create temp file with new header
        echo "$SPECIFIC_HEADER" > temp_file
        echo "" >> temp_file

        # Add the rest of the file, skipping any existing header comments and removing inline comments
        awk '
        BEGIN { in_header = 0; found_namespace = 0 }
        /^\/\*/ { in_header = 1; next }
        /^\*\// && in_header { in_header = 0; next }
        in_header { next }
        /^using|^namespace/ && !found_namespace { found_namespace = 1; print; next }
        found_namespace && /^\s*\/\/[^\/]/ { next }
        found_namespace { print }
        !found_namespace { print }
        ' "$file" >> temp_file

        mv temp_file "$file"
    fi
done

echo "Headers updated successfully!"