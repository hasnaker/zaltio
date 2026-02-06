/**
 * Dashboard Components
 * 
 * Exports all dashboard-related components for the Zalt.io Auth Platform.
 */

// Clerk-style components (new)
export { ClerkSidebar } from './ClerkSidebar';
export type { ClerkSidebarProps } from './ClerkSidebar';

export { ClerkHeader } from './ClerkHeader';
export type { ClerkHeaderProps } from './ClerkHeader';

export { 
  DashboardCard, 
  DashboardStatGrid, 
  DashboardSection, 
  DashboardTableCard 
} from './DashboardCard';
export type { 
  DashboardCardProps, 
  DashboardStatGridProps, 
  DashboardSectionProps, 
  DashboardTableCardProps 
} from './DashboardCard';

// Legacy components
export { Sidebar } from './Sidebar';
export type { SidebarProps, NavItem } from './Sidebar';

export { HeaderBar } from './HeaderBar';
export type { HeaderBarProps } from './HeaderBar';

export { Breadcrumb } from './Breadcrumb';
export type { BreadcrumbProps, BreadcrumbItem } from './Breadcrumb';

export { NotificationPanel } from './NotificationPanel';
export type { NotificationPanelProps } from './NotificationPanel';

export { RecentActivity } from './RecentActivity';
export type { RecentActivityProps, ActivityItem, ActivityType } from './RecentActivity';

export { QuickActions } from './QuickActions';
export type { QuickActionsProps, QuickAction } from './QuickActions';

export { MiniChart } from './MiniChart';
export type { MiniChartProps, ChartDataPoint, ChartType } from './MiniChart';
