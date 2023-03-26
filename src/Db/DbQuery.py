import re


class DbQuery:
    def __init__(self, query):
        self.setQuery(query.strip())

    def parseParts(self, query):
        parts = re.split("(SELECT|FROM|WHERE|ORDER BY|LIMIT)", query)
        parts = [_f for _f in parts if _f]
        parts = [s.strip() for s in parts]
        return dict(list(zip(parts[0::2], parts[1::2])))

    def parseFields(self, query_select):
        fields = re.findall("([^,]+) AS ([^,]+)", query_select)
        return {key: val.strip() for val, key in fields}

    def parseWheres(self, query_where):
        if " AND " in query_where:
            return query_where.split(" AND ")
        elif query_where:
            return [query_where]
        else:
            return []

    def setQuery(self, query):
        self.parts = self.parseParts(query)
        self.fields = self.parseFields(self.parts["SELECT"])
        self.wheres = self.parseWheres(self.parts.get("WHERE", ""))

    def __str__(self):
        query_parts = []
        for part_name in ["SELECT", "FROM", "WHERE", "ORDER BY", "LIMIT"]:
            if part_name == "WHERE" and self.wheres:
                query_parts.append("WHERE")
                query_parts.append(" AND ".join(self.wheres))
            elif part_name in self.parts:
                query_parts.append(part_name)
                query_parts.append(self.parts[part_name])
        return "\n".join(query_parts)
