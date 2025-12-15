import React from "react";
import {
  Grid,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";

const sampleData = {
  trivy: [
    { id: 1, vuln: "CVE-2023-1234", severity: "HIGH" },
    { id: 2, vuln: "CVE-2023-5678", severity: "MEDIUM" },
  ],
  bandit: [
    { id: 1, issue: "Use of eval()", severity: "HIGH" },
    { id: 2, issue: "Hardcoded password", severity: "MEDIUM" },
  ],
  dpCheck: [
    { id: 1, dependency: "lodash", severity: "LOW" },
    { id: 2, dependency: "express", severity: "HIGH" },
  ],
};

const TableBlock = ({ title, columns, data }) => (
  <Paper elevation={3} sx={{ padding: 2 }}>
    <Typography variant="h6" gutterBottom>
      {title}
    </Typography>
    <TableContainer>
      <Table size="small">
        <TableHead>
          <TableRow>
            {columns.map((col) => (
              <TableCell key={col}>{col}</TableCell>
            ))}
          </TableRow>
        </TableHead>
        <TableBody>
          {data.map((row) => (
            <TableRow key={row.id}>
              {columns.map((col) => (
                <TableCell key={col}>{row[col.toLowerCase()]}</TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  </Paper>
);

const Dashboard = () => {
  return (
    <Grid
      container
      spacing={2}
      sx={{
        height: "100vh", // cała wysokość okna
        display: "flex",
        justifyContent: "center", // horyzontalne wycentrowanie
        alignItems: "center", // wertykalne wycentrowanie
        padding: 2,
      }}
    >
      <Grid container item xs={12} md={10} spacing={2} justifyContent="center">
        <Grid item xs={12} md={4}>
          <TableBlock
            title="Trivy"
            columns={["Vuln", "Severity"]}
            data={sampleData.trivy}
          />
        </Grid>
        <Grid item xs={12} md={4}>
          <TableBlock
            title="Bandit"
            columns={["Issue", "Severity"]}
            data={sampleData.bandit}
          />
        </Grid>
        <Grid item xs={12} md={4}>
          <TableBlock
            title="Dependency-Check"
            columns={["Dependency", "Severity"]}
            data={sampleData.dpCheck}
          />
        </Grid>
      </Grid>
    </Grid>
  );
};

export default Dashboard;
