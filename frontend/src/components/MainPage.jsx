import Dashboard from "./MainPage/Dashboard.jsx";
import Gauge from "./MainPage/Gauge.jsx";
import Container from "@mui/material/Container";
export default function MainPage() {
  return (
    <Container
      minWidth="100wh"
      sx={{ display: "flex", alignItems: "center", flexDirection: "column" }}
    >
      <Gauge />
      <Dashboard />
    </Container>
  );
}
