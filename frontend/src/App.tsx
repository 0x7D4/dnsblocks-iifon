import { useState } from 'react';
import { LoadingAnimation } from './components/LoadingAnimation';
import { Sidebar } from './components/Sidebar';
import { DashboardContent } from './components/DashboardContent';

function App() {
  const [loading, setLoading] = useState(true);

  return (
    <div className="flex h-screen w-full bg-[#121212] overflow-hidden text-foreground">
      {loading && <LoadingAnimation onComplete={() => setLoading(false)} />}

      {!loading && (
        <>
          <Sidebar />
          <DashboardContent />
        </>
      )}
    </div>
  );
}

export default App;
