import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import networkx as nx
import numpy as np
import base64
import io
import json
from collections import Counter
import seaborn as sns

# Set matplotlib to use a backend that doesn't require a display
plt.switch_backend('Agg')

# Set dark theme for graphs
plt.style.use('dark_background')

class AnalysisVisualizer:
    def __init__(self):
        self.colors = {
            'primary': '#00ff00',
            'secondary': '#66ff66',
            'warning': '#ffff00',
            'danger': '#ff0000',
            'background': '#0c0c0c',
            'surface': '#001100'
        }
    
    def create_process_tree_graph(self, process_tree_data):
        """Create a visual process tree graph"""
        if not process_tree_data or 'tree' not in process_tree_data:
            return None
        
        fig, ax = plt.subplots(figsize=(12, 8))
        fig.patch.set_facecolor(self.colors['background'])
        ax.set_facecolor(self.colors['background'])
        
        # Create directed graph
        G = nx.DiGraph()
        
        # Add nodes and edges
        processes = process_tree_data['tree']
        for pid, proc_info in processes.items():
            # Add node with attributes
            status_color = self.colors['primary'] if proc_info['status'] == 'running' else self.colors['danger']
            G.add_node(pid, 
                      label=f"PID:{pid}\n{proc_info.get('executable', 'unknown')}", 
                      color=status_color,
                      status=proc_info['status'])
            
            # Add edge from parent
            if proc_info['parent_pid'] in processes:
                G.add_edge(proc_info['parent_pid'], pid)
        
        if len(G.nodes()) == 0:
            ax.text(0.5, 0.5, 'No process data available', 
                   ha='center', va='center', color=self.colors['primary'],
                   transform=ax.transAxes, fontsize=14)
        else:
            # Use hierarchical layout
            pos = nx.spring_layout(G, k=3, iterations=50)
            
            # Draw edges
            nx.draw_networkx_edges(G, pos, edge_color=self.colors['secondary'], 
                                 arrows=True, arrowsize=20, arrowstyle='->', 
                                 width=2, alpha=0.7)
            
            # Draw nodes with different colors based on status
            running_nodes = [n for n, d in G.nodes(data=True) if d.get('status') == 'running']
            exited_nodes = [n for n, d in G.nodes(data=True) if d.get('status') != 'running']
            
            if running_nodes:
                nx.draw_networkx_nodes(G, pos, nodelist=running_nodes, 
                                     node_color=self.colors['primary'], 
                                     node_size=1500, alpha=0.8)
            
            if exited_nodes:
                nx.draw_networkx_nodes(G, pos, nodelist=exited_nodes, 
                                     node_color=self.colors['danger'], 
                                     node_size=1500, alpha=0.8)
            
            # Draw labels
            labels = {n: d['label'] for n, d in G.nodes(data=True)}
            nx.draw_networkx_labels(G, pos, labels, font_size=8, 
                                   font_color='white', font_weight='bold')
        
        ax.set_title('Process Execution Tree', color=self.colors['primary'], 
                    fontsize=16, fontweight='bold', pad=20)
        ax.axis('off')
        
        # Add legend
        running_patch = mpatches.Patch(color=self.colors['primary'], label='Running')
        exited_patch = mpatches.Patch(color=self.colors['danger'], label='Exited')
        ax.legend(handles=[running_patch, exited_patch], loc='upper right', 
                 facecolor=self.colors['surface'], edgecolor=self.colors['primary'])
        
        return self._fig_to_base64(fig)
    
    def create_syscall_frequency_chart(self, syscall_analysis):
        """Create a bar chart of system call frequencies"""
        if not syscall_analysis or 'syscall_frequency' not in syscall_analysis:
            return None
        
        fig, ax = plt.subplots(figsize=(12, 6))
        fig.patch.set_facecolor(self.colors['background'])
        ax.set_facecolor(self.colors['background'])
        
        syscall_freq = syscall_analysis['syscall_frequency']
        
        if not syscall_freq:
            ax.text(0.5, 0.5, 'No syscall data available', 
                   ha='center', va='center', color=self.colors['primary'],
                   transform=ax.transAxes, fontsize=14)
        else:
            # Get top 15 syscalls
            top_syscalls = dict(list(syscall_freq.items())[:15])
            
            syscalls = list(top_syscalls.keys())
            counts = list(top_syscalls.values())
            
            # Create bars with gradient effect
            bars = ax.bar(syscalls, counts, color=self.colors['primary'], alpha=0.8)
            
            # Highlight suspicious syscalls
            suspicious_syscalls = {'execve', 'socket', 'connect', 'unlink', 'kill', 'fork', 'clone'}
            for i, syscall in enumerate(syscalls):
                if syscall in suspicious_syscalls:
                    bars[i].set_color(self.colors['danger'])
                    bars[i].set_alpha(0.9)
            
            ax.set_xlabel('System Calls', color=self.colors['primary'], fontsize=12)
            ax.set_ylabel('Frequency', color=self.colors['primary'], fontsize=12)
            ax.set_title('System Call Frequency Distribution', 
                        color=self.colors['primary'], fontsize=14, fontweight='bold')
            
            # Rotate x-axis labels
            plt.xticks(rotation=45, ha='right', color=self.colors['secondary'])
            plt.yticks(color=self.colors['secondary'])
            
            # Add grid
            ax.grid(True, alpha=0.3, color=self.colors['secondary'])
            
            # Add value labels on bars
            for bar, count in zip(bars, counts):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height + max(counts) * 0.01,
                       f'{count}', ha='center', va='bottom', 
                       color=self.colors['secondary'], fontsize=8)
        
        plt.tight_layout()
        return self._fig_to_base64(fig)
    
    def create_syscall_timeline(self, syscalls):
        """Create a timeline of system call activity"""
        if not syscalls:
            return None
        
        fig, ax = plt.subplots(figsize=(14, 8))
        fig.patch.set_facecolor(self.colors['background'])
        ax.set_facecolor(self.colors['background'])
        
        # Prepare data
        timestamps = [sc['timestamp'] for sc in syscalls]
        syscall_names = [sc['name'] for sc in syscalls]
        pids = [sc['pid'] for sc in syscalls]
        
        if not timestamps:
            ax.text(0.5, 0.5, 'No syscall timeline data available', 
                   ha='center', va='center', color=self.colors['primary'],
                   transform=ax.transAxes, fontsize=14)
        else:
            # Normalize timestamps
            min_time = min(timestamps)
            relative_times = [(t - min_time) for t in timestamps]
            
            # Create a scatter plot colored by PID
            unique_pids = list(set(pids))
            colors_map = plt.cm.get_cmap('tab10')
            
            for i, pid in enumerate(unique_pids):
                pid_indices = [j for j, p in enumerate(pids) if p == pid]
                pid_times = [relative_times[j] for j in pid_indices]
                pid_syscalls = [syscall_names[j] for j in pid_indices]
                
                # Map syscalls to y-values
                unique_syscalls = list(set(syscall_names))
                y_values = [unique_syscalls.index(sc) for sc in pid_syscalls]
                
                ax.scatter(pid_times, y_values, 
                          color=colors_map(i % 10), label=f'PID {pid}', 
                          alpha=0.7, s=30)
            
            ax.set_xlabel('Time (seconds from start)', color=self.colors['primary'], fontsize=12)
            ax.set_ylabel('System Calls', color=self.colors['primary'], fontsize=12)
            ax.set_title('System Call Timeline', 
                        color=self.colors['primary'], fontsize=14, fontweight='bold')
            
            # Set y-tick labels to syscall names
            unique_syscalls = list(set(syscall_names))
            ax.set_yticks(range(len(unique_syscalls)))
            ax.set_yticklabels(unique_syscalls, color=self.colors['secondary'], fontsize=8)
            
            ax.tick_params(axis='x', colors=self.colors['secondary'])
            ax.grid(True, alpha=0.3, color=self.colors['secondary'])
            
            # Add legend if not too many PIDs
            if len(unique_pids) <= 8:
                ax.legend(bbox_to_anchor=(1.05, 1), loc='upper left', 
                         facecolor=self.colors['surface'], 
                         edgecolor=self.colors['primary'])
        
        plt.tight_layout()
        return self._fig_to_base64(fig)
    
    def create_analysis_summary_chart(self, analysis_data):
        """Create a summary chart of analysis metrics"""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(14, 10))
        fig.patch.set_facecolor(self.colors['background'])
        
        for ax in [ax1, ax2, ax3, ax4]:
            ax.set_facecolor(self.colors['background'])
        
        syscall_analysis = analysis_data.get('syscall_analysis', {})
        
        # 1. Operation types pie chart
        operations = {
            'File Operations': syscall_analysis.get('file_operations', 0),
            'Network Operations': syscall_analysis.get('network_operations', 0),
            'Process Operations': syscall_analysis.get('process_operations', 0),
            'Memory Operations': syscall_analysis.get('memory_operations', 0)
        }
        
        # Filter out zero values
        operations = {k: v for k, v in operations.items() if v > 0}
        
        if operations:
            colors = [self.colors['primary'], self.colors['secondary'], 
                     self.colors['warning'], self.colors['danger']]
            wedges, texts, autotexts = ax1.pie(operations.values(), labels=operations.keys(), 
                                              autopct='%1.1f%%', colors=colors[:len(operations)])
            for text in texts + autotexts:
                text.set_color('white')
        else:
            ax1.text(0.5, 0.5, 'No operation data', ha='center', va='center', 
                    color=self.colors['primary'], transform=ax1.transAxes)
        
        ax1.set_title('Operation Types Distribution', color=self.colors['primary'], fontweight='bold')
        
        # 2. Process count over time (if available)
        processes = analysis_data.get('processes', [])
        if processes:
            start_times = [p.get('timestamp', 0) for p in processes if 'timestamp' in p]
            if start_times:
                ax2.hist(start_times, bins=20, color=self.colors['primary'], alpha=0.7)
                ax2.set_xlabel('Time', color=self.colors['primary'])
                ax2.set_ylabel('Process Count', color=self.colors['primary'])
                ax2.tick_params(colors=self.colors['secondary'])
            else:
                ax2.text(0.5, 0.5, 'No timing data', ha='center', va='center', 
                        color=self.colors['primary'], transform=ax2.transAxes)
        else:
            ax2.text(0.5, 0.5, 'No process data', ha='center', va='center', 
                    color=self.colors['primary'], transform=ax2.transAxes)
        
        ax2.set_title('Process Activity Timeline', color=self.colors['primary'], fontweight='bold')
        
        # 3. Suspicious patterns count
        patterns = syscall_analysis.get('suspicious_patterns', [])
        if patterns:
            pattern_types = ['Execve Injection', 'Network Activity', 'File Deletion', 'Other']
            pattern_counts = [0, 0, 0, 0]
            
            for pattern in patterns:
                if 'execve' in pattern.lower():
                    pattern_counts[0] += 1
                elif 'network' in pattern.lower() or 'socket' in pattern.lower():
                    pattern_counts[1] += 1
                elif 'deletion' in pattern.lower() or 'unlink' in pattern.lower():
                    pattern_counts[2] += 1
                else:
                    pattern_counts[3] += 1
            
            bars = ax3.bar(pattern_types, pattern_counts, color=self.colors['danger'], alpha=0.8)
            ax3.set_ylabel('Count', color=self.colors['primary'])
            ax3.tick_params(colors=self.colors['secondary'])
            plt.setp(ax3.get_xticklabels(), rotation=45, ha='right')
        else:
            ax3.text(0.5, 0.5, 'No suspicious patterns', ha='center', va='center', 
                    color=self.colors['primary'], transform=ax3.transAxes)
        
        ax3.set_title('Suspicious Pattern Categories', color=self.colors['primary'], fontweight='bold')
        
        # 4. Memory and network usage metrics
        metrics = {
            'Total Syscalls': analysis_data.get('total_syscalls', 0),
            'Total Processes': analysis_data.get('total_processes', 0),
            'Unique Syscalls': syscall_analysis.get('unique_syscalls', 0),
            'Suspicious Patterns': len(patterns)
        }
        
        metric_names = list(metrics.keys())
        metric_values = list(metrics.values())
        
        bars = ax4.barh(metric_names, metric_values, color=self.colors['secondary'], alpha=0.8)
        ax4.set_xlabel('Count', color=self.colors['primary'])
        ax4.tick_params(colors=self.colors['secondary'])
        
        # Add value labels
        for i, (bar, value) in enumerate(zip(bars, metric_values)):
            ax4.text(value + max(metric_values) * 0.01, bar.get_y() + bar.get_height()/2,
                    str(value), ha='left', va='center', color=self.colors['secondary'])
        
        ax4.set_title('Analysis Summary Metrics', color=self.colors['primary'], fontweight='bold')
        
        plt.tight_layout()
        return self._fig_to_base64(fig)
    
    def _fig_to_base64(self, fig):
        """Convert matplotlib figure to base64 string"""
        buffer = io.BytesIO()
        fig.savefig(buffer, format='png', dpi=150, bbox_inches='tight', 
                   facecolor=self.colors['background'], edgecolor='none')
        buffer.seek(0)
        
        img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        plt.close(fig)  # Free memory
        
        return img_base64