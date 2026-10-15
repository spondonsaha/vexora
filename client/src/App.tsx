import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { OnboardingPage } from './pages/OnboardingPage'
import { ScopeTargetsPage } from './pages/ScopeTargetsPage'
import { ScopeTargetDetailPage } from './pages/ScopeTargetDetailPage'
import { DashboardPage } from './pages/DashboardPage'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Navigate to="/onboarding" replace />} />
          <Route path="/onboarding" element={<OnboardingPage />} />
          <Route path="/targets" element={<ScopeTargetsPage />} />
          <Route path="/targets/:id" element={<ScopeTargetDetailPage />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="*" element={<Navigate to="/onboarding" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
